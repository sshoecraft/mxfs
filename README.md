# MXFS — Multinode XFS

A shared/clustered filesystem that extends Linux XFS to support concurrent
read/write access from multiple nodes to the same block device. No external
cluster stack required — no corosync, no pacemaker, no fencing agents.

## Overview

MXFS adds a distributed lock coordination layer on top of standard XFS.
Two components run on each node:

- **mxfs.ko** — Kernel module that hooks into XFS lock points and
  communicates with the userspace daemon via Generic Netlink
- **mxfsd** — Userspace daemon that manages peer connections, runs the
  DLM protocol, handles lease-based node liveness, and coordinates
  journal recovery

The core design folds everything into one smart DLM layer. Node liveness,
fencing, recovery, and cache coherency all derive from lock state. A node
that holds locks is alive. A node whose leases expire is dead — its locks
are invalidated and its journal is replayed.

## Architecture

```
Node A                              Node B
┌──────────────┐                    ┌──────────────┐
│  XFS kernel  │                    │  XFS kernel  │
│      │       │                    │      │       │
│  mxfs.ko     │                    │  mxfs.ko     │
│      │       │                    │      │       │
│  (netlink)   │                    │  (netlink)   │
└──────┼───────┘                    └──────┼───────┘
       │                                   │
┌──────┼───────┐                    ┌──────┼───────┐
│   mxfsd      │◄──────TCP────────►│   mxfsd      │
└──────────────┘                    └──────────────┘
       │                                   │
       └──────── shared block device ──────┘
```

## Target UX

```bash
# Format with standard XFS
mkfs.xfs /dev/sdb1

# Node 1
mxfsd start --config /etc/mxfs/volumes.conf
mount -t xfs /dev/sdb1 /mnt/shared

# Node 2
mxfsd start --config /etc/mxfs/volumes.conf
mount -t xfs /dev/sdb1 /mnt/shared
```

## Building

### Daemon

```bash
make daemon
```

Produces the `mxfsd` binary. Requires gcc with C11 support and pthreads.

### Kernel Module

```bash
make kernel
```

Requires kernel headers for the target kernel.

## Configuration

See `config/volumes.conf.example` for a complete example. INI-style format
with sections:

- `[node]` — Local node identity (id, name, bind address, port)
- `[peer]` — Remote peer endpoints (multiple sections allowed)
- `[volume]` — Shared XFS volumes (multiple sections allowed)
- `[timing]` — Lease and timeout parameters
- `[logging]` — Log file, level, syslog, daemonize

Default port: 7600

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
├── kernel/                Kernel module (netlink, XFS hooks, cache invalidation)
├── daemon/                Daemon (config, peer, DLM, netlink, lease, journal, volume, log)
├── config/                Example configuration
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
