# MXFS — Multinode XFS

A shared/clustered filesystem that extends Linux XFS to support concurrent
read/write access from multiple nodes to the same block device. No external
cluster stack required — no corosync, no pacemaker, no fencing agents.

## Overview

MXFS is a stacking filesystem (like ecryptfs/overlayfs) that wraps XFS at
the VFS layer. Two components run on each node:

- **mxfs.ko** — Kernel module that registers filesystem type `mxfs`. On
  mount, it internally mounts XFS, spawns the daemon, and wraps every VFS
  operation with distributed lock acquire/release via Generic Netlink.
- **mxfsd** — Userspace daemon that manages peer connections, runs the
  DLM protocol, handles lease-based node liveness, SCSI-3 PR hardware
  fencing, on-disk lock persistence, and coordinates journal recovery.
  Spawned automatically by the kernel module — no manual management.

## Architecture

```
Node A                              Node B
┌──────────────┐                    ┌──────────────┐
│   mxfs.ko    │                    │   mxfs.ko    │
│  (stacking)  │                    │  (stacking)  │
│      │       │                    │      │       │
│  XFS (lower) │                    │  XFS (lower) │
│      │       │                    │      │       │
│  (netlink)   │                    │  (netlink)   │
└──────┼───────┘                    └──────┼───────┘
       │                                   │
┌──────┼───────┐                    ┌──────┼───────┐
│   mxfsd      │◄──────TCP────────►│   mxfsd      │
│              │◄──────UDP────────►│              │
└──────────────┘                    └──────────────┘
       │                                   │
       └──────── shared block device ──────┘
```

## Usage

```bash
# Format with standard XFS (one time)
mkfs.xfs /dev/sdb

# Mount on each node — everything starts automatically
mount -t mxfs /dev/sdb /mnt/shared

# Optional: specify interface, port, or discovery mode
mount -t mxfs -o iface=eth0,port=7600 /dev/sdb /mnt/shared

# Unmount — everything stops automatically
umount /mnt/shared
```

No config files. No manual daemon management. No separate start/stop.
Zero-config multicast discovery (239.66.83.1:7601) finds peers automatically.

## Building

### Daemon

```bash
make daemon
```

Produces the `mxfsd` binary. Install to `/usr/sbin/mxfsd`. Requires gcc
with C11 support and pthreads.

### Kernel Module

```bash
make kernel
```

Requires kernel headers for the target kernel.

## Mount Options

All optional — defaults work for most configurations:

| Option | Default | Description |
|--------|---------|-------------|
| `iface=` | (auto) | Network interface for discovery and DLM traffic |
| `port=` | 7600 | TCP port for DLM peer connections |
| `multicast=` | 239.66.83.1 | Multicast group for UDP peer discovery |
| `broadcast=` | (none) | Use broadcast instead of multicast for discovery |

## Three-Layer Fencing (VMFS-style)

1. **SCSI-3 PR** (hardware) — WRITE EXCLUSIVE REGISTRANTS ONLY reservation.
   Storage array rejects all I/O from fenced nodes. Zero cost on lock hot path.
2. **On-disk lockstate** (persistent) — Lock grants written to `.mxfs/lockstate`
   via O_DIRECT sector-aligned I/O. Survives daemon restarts.
3. **TCP DLM** (performance) — In-memory distributed lock negotiation.
   Per-resource mastering via FNV-1a hash across all active nodes.

## DLM Lock Modes

Standard 6-mode compatibility matrix (same lineage as VMS DLM):

| | NL | CR | CW | PR | PW | EX |
|---|---|---|---|---|---|---|
| **NL** | Y | Y | Y | Y | Y | Y |
| **CR** | Y | Y | Y | Y | Y | N |
| **CW** | Y | Y | Y | N | N | N |
| **PR** | Y | Y | N | Y | N | N |
| **PW** | Y | Y | N | N | N | N |
| **EX** | Y | N | N | N | N | N |

Lock types: Inode, Extent, Allocation Group, Journal, Superblock.

## Project Structure

```
mxfs/
├── include/mxfs/          Shared headers (common types, DLM protocol, netlink)
├── kernel/                Kernel module (stacking FS, netlink, cache invalidation)
├── daemon/                Daemon (DLM, peer, discovery, SCSI PR, disklock, lease, journal)
├── tools/                 Test tools (mxfs_lock)
├── config/                Example configuration (legacy)
└── docs/                  Architecture and protocol documentation
```

## Documentation

- `docs/architecture.md` — System architecture overview
- `docs/dlm-protocol.md` — DLM wire protocol specification
- `kernel/kernel.md` — Kernel module internals
- `daemon/daemon.md` — Daemon internals
- `INFO.md` — Working notes and design decisions

## Why Not Existing Solutions?

- **OCFS2** — Corruption-prone, effectively in maintenance mode
- **GFS2** — Requires full Red Hat cluster stack (corosync, pacemaker, fencing)
- **GlusterFS** — Red Hat ended commercial support (2024). Distributed, not shared-disk. FUSE performance.
- **VMFS** — Purpose-built for VM storage (small number of large files). Not general-purpose.

MXFS aims to be what VMFS is for VMware, but as a general-purpose shared
filesystem for Linux — self-contained, no external cluster stack, the disk
is the arbiter.

## License

GPL-2.0
