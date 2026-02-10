# mxfs.ko — Kernel Module

## Overview

The MXFS kernel module is the thin, fast-path component that hooks into XFS
lock points and communicates with the mxfsd userspace daemon via Generic
Netlink (genetlink).

## Architecture

### Components

- **mxfs_main.c** — Module entry/exit, subsystem initialization ordering
- **mxfs_netlink.c** — Genetlink family registration, message send/receive
  with the local mxfsd daemon
- **mxfs_hooks.c** — XFS lock intercepts for inodes, extents, and allocation
  groups. When a local XFS operation needs a resource that may be contended
  across nodes, the hook forwards the request through netlink to mxfsd and
  blocks until the distributed lock is granted.
- **mxfs_cache.c** — Page cache invalidation. When the DLM indicates that a
  remote node has modified data under a resource we're acquiring, we must
  invalidate stale cached pages before allowing local reads.

### Communication Flow

```
XFS thread needs inode lock
        |
        v
mxfs_hooks intercepts
        |
        v
mxfs_netlink sends LOCK_REQ to mxfsd
        |
        v
(blocks waiting for response)
        |
        v
mxfsd sends LOCK_GRANT back
        |
        v
mxfs_cache invalidates if needed
        |
        v
XFS thread continues with lock held
```

### Build

Requires kernel headers for the target kernel:

```
make -C kernel KDIR=/path/to/kernel/build
```

## mxfs_netlink.c — Implementation Details

### Genetlink Family
- Registers family name "mxfs" version 1 via `genl_register_family()`
- Defines attribute policy for all `MXFS_NL_ATTR_*` types
- Two multicast groups: "locks" and "status"

### Operations Table
All 12 `MXFS_NL_CMD_*` commands are registered in the ops table:
- **LOCK_REQ** / **LOCK_RELEASE** — kernel-originated (doit=NULL), sent via helpers
- **LOCK_GRANT** — daemon sends grant; handler completes the pending request
- **LOCK_DENY** — daemon denies; handler completes with error status
- **CACHE_INVAL** — daemon requests page cache invalidation; delegates to `mxfs_cache_invalidate()`
- **NODE_STATUS** — daemon reports node state changes; stored in `node_states[]`
- **VOLUME_MOUNT** / **VOLUME_UMOUNT** — records daemon portid on ack
- **STATUS_REQ** / **STATUS_RESP** — daemon registration handshake, captures portid
- **RECOVERY_START** / **RECOVERY_DONE** — delegates to `mxfs_hooks_recovery_start/done()`

### Pending Lock Requests
- 256-bucket hash table keyed on `mxfs_resource_id`
- Each pending request has a `struct completion` for blocking the XFS thread
- `mxfs_nl_send_lock_req()` inserts into hash, sends message, blocks with 30s timeout
- On grant/deny, handler looks up by resource and calls `complete()`

### Daemon Connection
- Daemon portid recorded on first STATUS_REQ or VOLUME_MOUNT
- All outgoing messages unicast to recorded portid via `genlmsg_unicast()`
- Returns -ENOTCONN if no daemon is connected

### Exported Functions (for hooks/cache)
- `mxfs_nl_send_lock_req()` — blocking lock request, returns granted mode
- `mxfs_nl_send_lock_release()` — fire-and-forget lock release
- `mxfs_nl_send_volume_mount()` — mount notification with device/mount paths
- `mxfs_nl_send_volume_umount()` — unmount notification
- `mxfs_nl_get_node_state()` — query cached node state

## mxfs_hooks.c — Implementation Details

### Recovery Freeze
- Per-volume recovery state: `mxfs_volume_state` with atomic recovering flag and waitqueue
- `mxfs_hooks_recovery_start()` — sets recovering=1, called by netlink on RECOVERY_START
- `mxfs_hooks_recovery_done()` — clears flag, wakes all waiters, called on RECOVERY_DONE
- All lock functions check `wait_for_recovery()` before sending request to daemon

### Resource ID Builders
- `build_inode_resource()` — type=INODE, volume+ino
- `build_extent_resource()` — type=EXTENT, volume+ino+offset
- `build_ag_resource()` — type=AG, volume+ag_number

### Exported Hook Functions
- `mxfs_hook_inode_lock/unlock()` — distributed inode locking
- `mxfs_hook_extent_lock/unlock()` — distributed extent range locking
- `mxfs_hook_ag_lock/unlock()` — distributed allocation group locking
- All lock functions block via `mxfs_nl_send_lock_req()` with 30s timeout
- All unlock functions are fire-and-forget via `mxfs_nl_send_lock_release()`

## mxfs_cache.c — Implementation Details

### Volume-to-Superblock Mapping
- 16-bucket hash table mapping volume IDs to `struct super_block *`
- `mxfs_cache_register_sb()` — register on mount
- `mxfs_cache_unregister_sb()` — unregister on unmount

### Invalidation
- `mxfs_cache_invalidate(volume, ino, offset, length)` — main entry point
- Looks up superblock from volume ID, finds inode via `ilookup()`
- If inode not in icache, returns 0 (nothing to invalidate)
- If length=0, calls `invalidate_inode_pages2()` for full invalidation
- Otherwise calls `invalidate_inode_pages2_range()` for partial range
- Drops inode reference via `iput()` after invalidation

## mxfs_main.c — Implementation Details

### Initialization Order
1. `mxfs_netlink_init()` — register genetlink family (must be first so hooks can send)
2. `mxfs_hooks_init()` — initialize XFS lock intercept state
3. `mxfs_cache_init()` — initialize page cache invalidation subsystem

### Error Rollback
If any init step fails, previously initialized subsystems are torn down in reverse:
- cache fail -> hooks_exit, netlink_exit
- hooks fail -> netlink_exit
- netlink fail -> return error

### Shutdown Order (reverse of init)
1. `mxfs_cache_exit()` — clean up superblock mappings
2. `mxfs_hooks_exit()` — remove XFS intercepts
3. `mxfs_netlink_exit()` — unregister genetlink family

### Module Metadata
- License: GPL
- Version: 0.4.0 (tracked in MODULE_VERSION)
- Prints version from MXFS_VERSION_MAJOR/MINOR/PATCH on load

## Version History

- 0.1.0 — Initial project structure, stub implementations
- 0.2.0 — Implemented mxfs_netlink.c: genetlink family, ops, pending lock tracking, send helpers
- 0.3.0 — Implemented mxfs_hooks.c: XFS lock intercepts with recovery freeze support
- 0.4.0 — Implemented mxfs_cache.c + mxfs_main.c: cache invalidation, module wiring with rollback
