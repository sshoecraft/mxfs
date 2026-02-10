# MXFS Architecture

## System Overview

MXFS consists of two components per node:

1. **mxfs.ko** (kernel module) — thin fast-path layer hooking into XFS
2. **mxfsd** (userspace daemon) — all coordination complexity

These communicate via Generic Netlink on the local node. Daemon instances
communicate with each other over TCP.

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

## The Smart DLM

Everything is locks and leases — one mechanism, one protocol:

- **Node liveness**: Hold locks = alive. Leases expire = dead.
- **Fencing**: Expired lease = fenced. Stale epoch = writes rejected.
- **Journal recovery**: Lease expires → lock claimant replays journal first.
- **Cache coherency**: Lock acquisition implies page cache invalidation.

## Lock Compatibility Matrix

Standard 6-mode DLM (same as VMS/OpenVMS DLM):

| Held \ Req | NL | CR | CW | PR | PW | EX |
|------------|----|----|----|----|----|----|
| **NL**     | Y  | Y  | Y  | Y  | Y  | Y  |
| **CR**     | Y  | Y  | Y  | Y  | Y  | N  |
| **CW**     | Y  | Y  | Y  | N  | N  | N  |
| **PR**     | Y  | Y  | N  | Y  | N  | N  |
| **PW**     | Y  | Y  | N  | N  | N  | N  |
| **EX**     | Y  | N  | N  | N  | N  | N  |

## Lock Resource Types

- **INODE** — per-inode metadata and data locks
- **EXTENT** — range locks for data extents
- **AG** — allocation group locks for space allocation
- **JOURNAL** — journal slot ownership
- **SUPER** — superblock lock for mount/unmount coordination

## Communication Protocols

### Kernel ↔ Daemon (Generic Netlink)
Defined in `include/mxfs/mxfs_netlink.h`. Commands for lock request/grant,
cache invalidation, volume mount/unmount, and recovery signaling.

### Daemon ↔ Daemon (TCP)
Defined in `include/mxfs/mxfs_dlm.h`. Length-prefixed messages with
`mxfs_dlm_msg_hdr`. Covers lock operations, lease management, node
join/leave, journal recovery, and cache invalidation coordination.

## Lease Timing

| Parameter             | Default  | Purpose                           |
|-----------------------|----------|-----------------------------------|
| lease_duration_ms     | 5000     | How long a lease is valid         |
| lease_renew_ms        | 2000     | How often to renew                |
| node_timeout_ms       | 15000    | When to declare a node dead       |
| lock_wait_timeout_ms  | 30000    | Max time to wait for a lock       |
| bast_timeout_ms       | 10000    | Time for holder to respond to BAST|
