# MXFS Architecture

## System Overview

MXFS is a stacking filesystem that wraps XFS at the Linux VFS layer.
Two components run on each node:

1. **mxfs.ko** (kernel module) — Stacking filesystem registered as type `mxfs`.
   Internally mounts XFS, spawns the daemon, delegates all VFS operations to
   XFS while wrapping them with distributed lock acquire/release.
2. **mxfsd** (userspace daemon) — All coordination complexity: peer connections,
   DLM protocol, SCSI-3 PR fencing, on-disk lock persistence, UDP discovery,
   lease management, and journal recovery.

These communicate via Generic Netlink on the local node. Daemon instances
communicate with each other over TCP (DLM) and UDP (discovery).

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

## Mount Sequence

```
1. User runs: mount -t mxfs [-o iface=eth0] /dev/sdb /mnt/shared
2. VFS calls mxfs_mount() / mxfs_fill_super()
3. mxfs.ko calls vfs_kern_mount("xfs") on the device
4. mxfs.ko reads XFS sb_uuid, derives volume_id via FNV-1a hash
5. mxfs.ko creates root inode wrapping XFS root
6. mxfs.ko registers with cache subsystem
7. mxfs.ko spawns mxfsd via call_usermodehelper():
     /usr/sbin/mxfsd --device /dev/sdb --mountpoint /mnt/shared --uuid <hex>
8. mxfsd initializes:
   a. SCSI-3 PR register + reserve (raw device)
   b. Open/create .mxfs/lockstate (on now-mounted XFS)
   c. Start disklock heartbeat
   d. Start UDP discovery (multicast 239.66.83.1:7601)
   e. Start TCP DLM, connect to discovered peers
9. mxfsd sends DAEMON_READY via netlink
10. mxfs.ko receives readiness, mount completes
```

## Unmount Sequence

```
1. User runs: umount /mnt/shared
2. VFS calls mxfs_kill_sb()
3. mxfs.ko sends SIGTERM to mxfsd
4. mxfsd shuts down:
   a. Release all DLM locks
   b. Stop discovery
   c. Disconnect peers
   d. Stop disklock heartbeat, close lockstate file
   e. SCSI PR unregister
   f. Exit
5. mxfs.ko unregisters from cache subsystem
6. mxfs.ko calls kern_unmount() on underlying XFS
7. mxfs.ko frees superblock info — unmount complete
```

## VFS Operation Flow

Every filesystem operation follows this pattern:

```
Application calls open/read/write/create/unlink/etc.
        |
        v
mxfs VFS op handler
        |
        v
mxfs_wait_for_recovery()     <- block if recovery in progress
        |
        v
mxfs_build_inode_resource()  <- build DLM resource ID
        |
        v
mxfs_nl_send_lock_req()      <- acquire DLM lock via netlink
        |
        v
(blocks waiting for LOCK_GRANT from daemon)
        |
        v
Delegate to lower XFS op     <- vfs_create/lookup_one_len/etc.
        |
        v
mxfs_nl_send_lock_release()  <- release DLM lock
        |
        v
fsstack_copy_attr_all()      <- sync attributes back
        |
        v
Return result to caller
```

## The DLM

Everything is locks and leases — one mechanism, one protocol:

- **Node liveness**: Hold locks = alive. Leases expire = dead.
- **Fencing**: Expired lease = fenced. SCSI PR preempt = hardware fence.
- **Journal recovery**: Lease expires -> lock claimant replays journal first.
- **Cache coherency**: Lock conflict (BAST) triggers page cache invalidation.

### Lock Mastering

Distributed per-resource mastering. Each resource hashes (FNV-1a) to a
master node from the sorted active node list:
`master = active_nodes[hash(resource) % node_count]`.
All nodes maintain the same sorted list so they agree deterministically.

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

## Three-Layer Fencing (VMFS-style)

1. **SCSI-3 PR** (hardware) — WRITE EXCLUSIVE REGISTRANTS ONLY reservation.
   All registered nodes can I/O; preempted nodes are fenced by the array.
   Zero cost on the lock hot path (one-time registration at startup).
2. **On-disk lockstate** (persistent) — Lock grants written to
   `.mxfs/lockstate` via O_DIRECT sector-aligned I/O. One 512-byte write
   per grant/release. Heartbeats written every 2 seconds.
3. **TCP DLM** (performance) — In-memory lock negotiation over TCP.
   Fast path for uncontested locks. Distributed mastering eliminates
   single-node bottleneck.

Fencing sequence on node death:
1. SCSI PREEMPT -> hardware blocks dead node's I/O
2. Disk purge -> clear dead node's lock records
3. Memory purge -> clear in-memory DLM state, promote waiters
4. Journal recovery -> replay dead node's XFS log

## Communication Protocols

### Kernel <-> Daemon (Generic Netlink)
Defined in `include/mxfs/mxfs_netlink.h`. Commands for lock request/grant,
cache invalidation, volume mount/unmount, daemon ready, and recovery signaling.
Per-mount portid tracking supports multiple concurrent mounts.

### Daemon <-> Daemon (TCP)
Defined in `include/mxfs/mxfs_dlm.h`. Length-prefixed messages with
`mxfs_dlm_msg_hdr`. Covers lock operations, lease management, node
join/leave, journal recovery, and cache invalidation coordination.
Default port: 7600.

### Discovery (UDP)
Defined in `daemon/mxfsd_discovery.h`. Periodic multicast/broadcast
announcements with node UUID, node ID, TCP port, volume UUID, hostname.
Default multicast group: 239.66.83.1:7601. Nodes sharing the same volume
UUID auto-form a lock group.

## Lease Timing

| Parameter             | Default  | Purpose                           |
|-----------------------|----------|-----------------------------------|
| lease_duration_ms     | 5000     | How long a lease is valid         |
| lease_renew_ms        | 2000     | How often to renew                |
| node_timeout_ms       | 15000    | When to declare a node dead       |
| lock_wait_timeout_ms  | 30000    | Max time to wait for a lock       |
| bast_timeout_ms       | 10000    | Time for holder to respond to BAST|
