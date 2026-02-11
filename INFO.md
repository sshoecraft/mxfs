# MXFS Project — Working Notes

## Project State

Version: 1.0.0 — Stacking filesystem architecture. MXFS is a proper Linux
stacking filesystem (like ecryptfs/overlayfs) that registers type `"mxfs"`
and wraps XFS at the VFS layer. On `mount -t mxfs /dev/sdb /mnt/shared`,
the kernel module mounts XFS internally, spawns mxfsd via
`call_usermodehelper()`, and the daemon handles SCSI PR fencing, on-disk
lock persistence, UDP discovery, TCP DLM, and cache coherency. Unmount
kills the daemon automatically. Zero config required.

## File Layout

```
mxfs/
├── INFO.md                          # this file
├── VERSION                          # semantic version string (1.0.0)
├── TASKS.md                         # implementation task checklist
├── refactor.md                      # stacking FS refactor design document
├── Makefile                         # top-level: delegates to daemon/ and kernel/
├── include/mxfs/
│   ├── mxfs_common.h                # shared types, constants, error codes
│   ├── mxfs_dlm.h                   # DLM protocol: lock modes, wire messages
│   └── mxfs_netlink.h               # genetlink commands/attributes (kern<->daemon)
├── kernel/
│   ├── Makefile                     # kbuild Makefile
│   ├── mxfs_main.c                  # module init/exit, register_filesystem("mxfs")
│   ├── mxfs_super.c                # mount/unmount, fill_super, daemon spawn/kill
│   ├── mxfs_inode.c                # inode operations with DLM lock integration
│   ├── mxfs_file.c                 # file operations with DLM lock integration
│   ├── mxfs_dir.c                  # directory operations with DLM lock integration
│   ├── mxfs_netlink.c              # kernel-side genetlink (per-mount portid)
│   ├── mxfs_cache.c                # page cache invalidation, volume->sb mapping
│   ├── mxfs_internal.h             # stacking FS data structures and accessors
│   └── kernel.md                   # module architecture doc
├── daemon/
│   ├── Makefile                     # daemon build
│   ├── mxfsd_main.c                # daemon entry point (kernel-spawned lifecycle)
│   ├── mxfsd_config.{c,h}          # config file parsing (retained for defaults)
│   ├── mxfsd_peer.{c,h}            # TCP peer connections (with dynamic peer add)
│   ├── mxfsd_dlm.{c,h}             # DLM protocol engine (distributed mastering)
│   ├── mxfsd_netlink.{c,h}         # userspace genetlink (DAEMON_READY support)
│   ├── mxfsd_lease.{c,h}           # lease management / node liveness
│   ├── mxfsd_journal.{c,h}         # journal recovery coordination
│   ├── mxfsd_log.{c,h}             # logging (file + syslog)
│   ├── mxfsd_volume.{c,h}          # volume state tracking
│   ├── mxfsd_scsi_pr.{c,h}        # SCSI-3 Persistent Reservations (I/O fencing)
│   ├── mxfsd_disklock.{c,h}       # on-disk lock state persistence
│   ├── mxfsd_discovery.{c,h}      # UDP peer discovery (multicast/broadcast)
│   ├── scsi_pr.md                  # SCSI PR module documentation
│   ├── disklock.md                 # disklock module documentation
│   ├── discovery.md                # discovery module documentation
│   └── daemon.md                   # daemon architecture doc
├── tools/
│   └── mxfs_lock.c                  # DLM test tool (lock/unlock via control socket)
├── config/
│   └── volumes.conf.example         # example configuration file
└── docs/
    ├── architecture.md              # system architecture overview
    └── dlm-protocol.md              # DLM wire protocol specification
```

## Architecture

### User Experience

```bash
mkfs.xfs /dev/sdb                         # standard XFS — nothing custom
mount -t mxfs /dev/sdb /mnt/shared        # everything starts automatically
# ... use the filesystem ...
umount /mnt/shared                         # everything stops automatically
```

Optional mount options: `-o iface=eth0,port=7600,multicast=239.66.83.1,broadcast=192.168.1.255`

### Stacking Model

MXFS is a stacking filesystem — it does not modify XFS source code. The kernel
module wraps XFS at the VFS layer. Each MXFS inode/dentry/file holds a pointer
to the corresponding lower XFS object. Every VFS operation:
1. Extracts the underlying XFS object
2. Acquires DLM lock via netlink to mxfsd
3. Calls the underlying XFS operation via VFS helpers
4. Releases the DLM lock
5. Copies attributes back up via `fsstack_copy_attr_all()`

### Mount Sequence

1. VFS calls mxfs_mount() / mxfs_fill_super()
2. mxfs.ko calls vfs_kern_mount("xfs") on the device
3. mxfs.ko reads XFS sb_uuid, derives volume_id via FNV-1a hash
4. mxfs.ko creates root inode wrapping XFS root
5. mxfs.ko registers with cache subsystem
6. mxfs.ko spawns mxfsd via call_usermodehelper()
7. mxfsd initializes: SCSI PR, disklock, DLM, discovery, peers
8. mxfsd sends DAEMON_READY via netlink
9. mxfs.ko receives readiness, mount completes

### Daemon Lifecycle

The daemon is spawned by the kernel module during mount and killed on unmount.
No standalone CLI, no daemonization, no PID file. The kernel provides all args:
`/usr/sbin/mxfsd --device /dev/sdb --mountpoint /mnt/shared --uuid <hex>`

## Key Design Decisions

### Lock Mode Compatibility
Using the standard 6-mode DLM (NL/CR/CW/PR/PW/EX) from the VMS lineage.
This is the same model used by GFS2 and OCFS2. The compatibility matrix is
fully defined in `mxfsd_dlm.c` as a static 6x6 array.

### Lock Mastering
Distributed per-resource mastering. Each resource hashes (FNV-1a) to a
master node from the sorted active node list:
`master = active_nodes[hash(resource) % node_count]`.
All nodes maintain the same sorted list so they agree deterministically.

### Three-Layer Fencing (VMFS-style)
1. **SCSI-3 PR** (hardware) — WRITE EXCLUSIVE REGISTRANTS ONLY reservation.
   All registered nodes can I/O; preempted nodes are fenced by the array.
   Zero cost on the lock hot path (one-time registration at startup).
2. **On-disk lockstate** (persistent) — Lock grants written to
   `.mxfs/lockstate` via O_DIRECT sector-aligned I/O. One 512-byte write
   per grant/release. Heartbeats written every 2 seconds.
3. **TCP DLM** (performance) — In-memory lock negotiation over TCP.
   Fast path for uncontested locks. Distributed mastering eliminates
   single-node bottleneck.

### Netlink vs Shared Memory
Starting with Generic Netlink for kernel<->daemon communication. This is
well-supported, debuggable (can use `genl` tools), and avoids the complexity
of shared memory ring buffers.

### Disk Format
Standard XFS — `mkfs.xfs` only. No custom on-disk metadata. The `.mxfs/`
directory is created at runtime by the daemon. No `mkfs.mxfs` needed.

### Node Identity
Persistent UUID at `/etc/mxfs/node.uuid`, generated on first run using
/dev/urandom (version 4 UUID). Node ID derived via FNV-1a hash.

### Threading Model
The daemon uses pthreads with dedicated threads for distinct I/O paths:
peer accept, peer receive, lease renewal, lease monitoring, netlink receive,
control socket, disklock heartbeat, discovery sender, discovery receiver.
The main thread handles signals and lifecycle.

### Default Ports
DLM: TCP 7600. Discovery: UDP 7601. Configurable via mount options.

## Dependencies

### Daemon Build
- gcc with C11 support
- pthreads
- No libnl dependency (raw AF_NETLINK socket)

### Kernel Module Build
- Kernel headers for target kernel
- Standard kbuild infrastructure

### Testing
- Two or more VMs/nodes with shared block device (iSCSI target recommended)
- XFS tools (xfsprogs)
