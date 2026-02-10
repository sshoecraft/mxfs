# MXFS Project — Working Notes

## Project State

Version: 0.1.0 — Initial project structure with stub implementations.
No functionality is implemented yet. All .c files contain function
signatures matching their headers but with empty bodies.

## File Layout

```
mxfs/
├── INFO.md                          # this file
├── VERSION                          # semantic version string
├── Makefile                         # top-level: delegates to daemon/ and kernel/
├── include/mxfs/
│   ├── mxfs_common.h                # shared types, constants, error codes
│   ├── mxfs_dlm.h                   # DLM protocol: lock modes, wire messages
│   └── mxfs_netlink.h               # genetlink commands/attributes (kern<->daemon)
├── kernel/
│   ├── Makefile                     # kbuild Makefile
│   ├── mxfs_main.c                  # module init/exit
│   ├── mxfs_netlink.c              # kernel-side genetlink
│   ├── mxfs_hooks.c                # XFS lock intercepts
│   ├── mxfs_cache.c                # page cache invalidation
│   └── kernel.md                   # module architecture doc
├── daemon/
│   ├── Makefile                     # daemon build
│   ├── mxfsd_main.c                # daemon entry point
│   ├── mxfsd_config.{c,h}          # config file parsing
│   ├── mxfsd_peer.{c,h}            # TCP peer connections
│   ├── mxfsd_dlm.{c,h}             # DLM protocol engine
│   ├── mxfsd_netlink.{c,h}         # userspace genetlink
│   ├── mxfsd_lease.{c,h}           # lease management / node liveness
│   ├── mxfsd_journal.{c,h}         # journal recovery coordination
│   ├── mxfsd_log.{c,h}             # logging (file + syslog)
│   ├── mxfsd_volume.{c,h}          # volume state tracking
│   └── daemon.md                   # daemon architecture doc
├── config/
│   └── volumes.conf.example         # example configuration file
└── docs/
    ├── architecture.md              # system architecture overview
    └── dlm-protocol.md              # DLM wire protocol specification
```

## Key Design Decisions

### Lock Mode Compatibility
Using the standard 6-mode DLM (NL/CR/CW/PR/PW/EX) from the VMS lineage.
This is the same model used by GFS2 and OCFS2. The compatibility matrix is
fully defined in `mxfsd_dlm.c` as a static 6x6 array.

### Lock Mastering
Each lock resource is mastered on a deterministic node via hash of the
resource ID. The master maintains the authoritative queue. This avoids
the need for a central lock server while keeping the protocol simple.

### Netlink vs Shared Memory
Starting with Generic Netlink for kernel<->daemon communication. This is
well-supported, debuggable (can use `genl` tools), and avoids the complexity
of shared memory ring buffers. Can optimize to shared memory later if
netlink proves to be a bottleneck.

### Config File Format
INI-style with sections: [node], [peer], [volume], [timing], [logging].
Multiple [peer] and [volume] sections allowed. Simple to parse without
external dependencies.

### Threading Model
The daemon uses pthreads with dedicated threads for distinct I/O paths:
peer accept, peer receive, lease renewal, lease monitoring, netlink receive.
The main thread handles signals and lifecycle. Mutexes protect shared state;
the lock table uses a rwlock for read-heavy access patterns.

### Default Port
7600 — chosen to avoid conflicts with common services. Configurable.

## Implementation Order (Recommended)

1. **Logging** (mxfsd_log) — needed by everything else
2. **Config parsing** (mxfsd_config) — needed to know who we are and who peers are
3. **Peer connections** (mxfsd_peer) — TCP listen/connect/send/receive
4. **DLM engine** (mxfsd_dlm) — lock table, compatibility checks, request processing
5. **Lease management** (mxfsd_lease) — renewal/monitoring threads
6. **Netlink** (mxfsd_netlink, kernel/mxfs_netlink) — kernel<->daemon channel
7. **XFS hooks** (kernel/mxfs_hooks) — intercept XFS lock operations
8. **Cache invalidation** (kernel/mxfs_cache, daemon cache_inval messages)
9. **Journal recovery** (mxfsd_journal) — slot management, recovery coordination
10. **Volume management** (mxfsd_volume) — mount/unmount coordination
11. **Main daemon** (mxfsd_main) — wire everything together

## Dependencies

### Daemon Build
- gcc with C11 support
- pthreads
- libnl (netlink library) — for genetlink userspace API

### Kernel Module Build
- Kernel headers for target kernel
- Standard kbuild infrastructure

### Testing
- Two or more VMs/nodes with shared block device (iSCSI target recommended)
- XFS tools (xfsprogs)
