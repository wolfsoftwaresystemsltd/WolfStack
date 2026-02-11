# WolfStack Storage Manager — Implementation Plan

## Overview
A centralized storage management system that lets the user mount remote and local storage from the WolfStack dashboard, propagate mounts across the cluster, and attach them to Docker containers, LXC containers, and VMs.

## Architecture

### Storage Config File
`/etc/wolfstack/storage.json` — persists all mount definitions.

```json
{
  "mounts": [
    {
      "id": "s3-backups",
      "name": "S3 Backups",
      "type": "s3",              // s3, nfs, directory, wolfdisk
      "source": "mybucket:",     // rclone remote, NFS server:/path, local path, wolfdisk path
      "mount_point": "/mnt/wolfstack/s3-backups",
      "enabled": true,
      "global": true,            // replicate to all cluster nodes
      "auto_mount": true,        // mount on boot
      "s3_config": {             // only for s3 type
        "access_key_id": "...",
        "secret_access_key": "...",
        "region": "eu-west-1",
        "endpoint": "",
        "provider": "AWS"
      },
      "nfs_options": "rw,sync",  // only for nfs type
      "status": "mounted",       // mounted, unmounted, error
      "created_at": "2026-02-11T04:00:00Z"
    }
  ]
}
```

## Implementation Steps (in order)

### Phase 1: Backend — Storage Module (Rust)
**File: `src/storage/mod.rs`** (new module)

1. **Data structures** — `StorageMount`, `StorageConfig`, `MountType` enum (S3, NFS, Directory, WolfDisk)
2. **Config persistence** — read/write `/etc/wolfstack/storage.json`
3. **Mount operations:**
   - `mount_s3()` — install rclone if needed, write rclone.conf entry, run `rclone mount`
   - `mount_nfs()` — install nfs-common if needed, run `mount -t nfs`
   - `mount_directory()` — run `mount --bind`
   - `mount_wolfdisk()` — run `wolfdiskctl mount`
   - `unmount()` — unmount any type
   - `get_status()` — check if mounted via `mountpoint` command
4. **S3 config import** — parse rclone.conf INI format, extract remotes
5. **Boot-time mounting** — function to mount all `auto_mount: true` entries

### Phase 2: Backend — API Endpoints
**File: `src/api/mod.rs`** (add to existing)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/storage/mounts` | List all mounts with status |
| POST   | `/api/storage/mounts` | Create a new mount |
| PUT    | `/api/storage/mounts/{id}` | Update a mount |
| DELETE | `/api/storage/mounts/{id}` | Remove a mount (unmount + delete config) |
| POST   | `/api/storage/mounts/{id}/mount` | Mount a storage |
| POST   | `/api/storage/mounts/{id}/unmount` | Unmount a storage |
| POST   | `/api/storage/import-rclone` | Import S3 configs from pasted rclone.conf |
| POST   | `/api/storage/mounts/{id}/sync` | Sync a global mount to all cluster nodes |

### Phase 3: Global Mounts — Cluster Replication
**In `src/storage/mod.rs`**

- When a mount is marked `global: true`, on create/update, push the config to all cluster nodes via the existing agent proxy mechanism
- Each node's storage module picks up the config and executes the mount
- Add an agent endpoint: `POST /api/agent/storage/apply` — receives mount config from leader and applies it locally

### Phase 4: Frontend — Storage Manager Page
**Files: `web/index.html` + `web/js/app.js`**

1. **Navigation** — Add "💾 Storage" item to server tree
2. **Page view** — `page-storage` div with:
   - Mount list table (name, type, source, mount point, status, global badge, actions)
   - Create mount modal with type-specific forms (S3 credentials, NFS server/path, directory path, WolfDisk path)
   - Import rclone.conf modal (textarea for pasting)
   - Mount/unmount/delete actions
3. **Container attachment UI** — In Docker create, LXC create, and VM detail pages, add a "Storage Mounts" dropdown to attach existing mounts as bind mounts

### Phase 5: VNC Clipboard (separate task)
**File: `web/vnc.html`**

- Add clipboard read/write integration using noVNC's clipboard API
- Add a paste button and clipboard sync toggle

---

## Implementation Order for this session

1. ✅ Create `src/storage/mod.rs` — data types + config + mount/unmount operations
2. ✅ Register module in `src/main.rs`
3. ✅ Add API endpoints in `src/api/mod.rs`
4. ✅ Add "Storage" nav item and page in `web/index.html`
5. ✅ Add JavaScript for Storage page in `web/js/app.js`
6. ✅ Add rclone.conf import functionality
7. ✅ Add global mount sync
8. ✅ Add mount attachment to container/LXC/VM create forms
9. ✅ VNC clipboard integration (separate)
