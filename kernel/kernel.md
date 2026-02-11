# mxfs.ko — Kernel Module

## Overview

The MXFS kernel module is a stacking filesystem (like ecryptfs/overlayfs) that
registers filesystem type `"mxfs"`. On `mount -t mxfs`, it internally mounts
XFS on the block device, spawns the mxfsd userspace daemon, and delegates all
VFS operations to XFS while wrapping them with distributed lock acquire/release
via Generic Netlink (genetlink) to the daemon.

## Architecture

### Components

- **mxfs_main.c** — Module entry/exit, subsystem initialization ordering.
  Registers filesystem type `mxfs` with the VFS.
- **mxfs_super.c** — Superblock operations: mount (`mxfs_fill_super`),
  unmount (`mxfs_kill_sb`), inode cache management, daemon lifecycle
  (`mxfs_spawn_daemon` / `mxfs_kill_daemon`), recovery wait, dentry
  operations, statfs delegation.
- **mxfs_inode.c** — Three inode_operations tables for directories, regular
  files, and symlinks. Each metadata operation acquires the appropriate DLM
  lock, delegates to XFS via VFS helpers (`vfs_create`, `lookup_one_len`,
  etc.), releases the lock, and copies attributes back up.
- **mxfs_file.c** — File operations for regular files: open, release, read,
  write, seek, mmap, fsync, ioctl, splice. Read/write swap `ki_filp` to the
  lower XFS file. Open/read/write/fsync wrapped with DLM locks.
- **mxfs_dir.c** — Directory file operations: readdir (`iterate_shared`)
  wraps `iterate_dir()` on the lower XFS directory. Readdir wrapped with
  DLM PR lock.
- **mxfs_netlink.c** — Genetlink family registration, message send/receive
  with the local mxfsd daemon. Per-mount portid tracking (supports multiple
  concurrent mounts). DAEMON_READY handler. Recovery start/done per-SBI state.
- **mxfs_cache.c** — Page cache invalidation. On DLM conflict (BAST), the
  daemon sends CACHE_INVAL, the kernel invalidates XFS pages. Volume-to-
  superblock mapping table. `mxfs_cache_find_sbi_by_volume()` for netlink
  handler lookups.

### Mount Sequence

```
1. VFS calls mxfs_mount() / mxfs_fill_super()
2. mxfs.ko calls vfs_kern_mount("xfs") on the device
3. mxfs.ko reads lower_sb->s_uuid for volume UUID, FNV-1a hash -> volume_id
4. mxfs.ko sets up root inode wrapping XFS root via mxfs_iget()
5. mxfs.ko registers with cache subsystem (mxfs_cache_register_sb)
6. mxfs.ko spawns mxfsd via call_usermodehelper():
     /usr/sbin/mxfsd --device /dev/sdb --mountpoint /mnt/shared --uuid <hex>
7. mxfsd initializes: SCSI PR, disklock, DLM, discovery, peers
8. mxfsd sends DAEMON_READY via netlink
9. mxfs.ko receives readiness, completes mount
```

### Unmount Sequence

```
1. VFS calls mxfs_kill_sb()
2. mxfs.ko sends SIGTERM to mxfsd via kill_pid()
3. mxfsd shuts down: release locks, stop discovery, disconnect peers,
   stop heartbeat, unregister SCSI PR, exit
4. mxfs.ko unregisters from cache subsystem
5. mxfs.ko calls kern_unmount() on underlying XFS
6. mxfs.ko frees superblock info
```

### VFS Operation Flow

```
Application calls open/read/write/create/unlink/etc.
        |
        v
mxfs VFS op handler
        |
        v
mxfs_wait_for_recovery(sbi)     ← block if recovery in progress
        |
        v
mxfs_build_inode_resource()      ← build DLM resource ID
        |
        v
mxfs_nl_send_lock_req()          ← acquire DLM lock via netlink
        |
        v
(blocks waiting for LOCK_GRANT)
        |
        v
Delegate to lower XFS operation  ← vfs_create/lookup_one_len/etc.
        |
        v
mxfs_nl_send_lock_release()      ← release DLM lock
        |
        v
fsstack_copy_attr_all()          ← sync attributes back
        |
        v
Return result to caller
```

### DLM Lock Policy

| Operation  | Lock Target    | Mode | Rationale                    |
|------------|----------------|------|------------------------------|
| create     | parent dir     | EX   | Modifies directory           |
| lookup     | parent dir     | PR   | Read-only dir scan           |
| link       | target dir     | EX   | Modifies directory           |
| unlink     | parent dir     | EX   | Modifies directory           |
| symlink    | parent dir     | EX   | Modifies directory           |
| mkdir      | parent dir     | EX   | Modifies directory           |
| rmdir      | parent dir     | EX   | Modifies directory           |
| rename     | both dirs (EX) | EX   | Lock in ino order (deadlock) |
| permission | target inode   | CR   | Minimal, concurrent OK       |
| getattr    | target inode   | PR   | Read-only                    |
| setattr    | target inode   | EX   | Modifies inode metadata      |
| open       | file inode     | CR   | Coherent inode needed        |
| release    | —              | none | Cleanup only                 |
| read_iter  | file inode     | PR   | Shared read                  |
| write_iter | file inode     | EX   | Exclusive write              |
| fsync      | file inode     | EX   | Flush + barrier              |
| readdir    | dir inode      | PR   | Read-only dir scan           |

### Build

Requires kernel headers for the target kernel:

```
make -C kernel KDIR=/path/to/kernel/build
```

## Data Structures

### Superblock Private Data (mxfs_sb_info)

Per-mount state stored in `sb->s_fs_info`:
- `lower_sb` / `lower_mnt` — underlying XFS superblock/vfsmount
- `volume_uuid[16]` / `volume_id` — XFS sb_uuid and FNV-1a hash
- `daemon_pid` / `daemon_portid` / `daemon_ready` — daemon process state
- `daemon_startup` — completion for blocking fill_super until daemon ready
- `iface` / `port` / `mcast_addr` / `bcast_addr` — mount options
- `dev_name` / `mount_path` — device and mountpoint strings
- `recovering` / `recovery_wait` — per-SBI recovery freeze state

### Inode Private Data (mxfs_inode_info)

- `lower_inode` — pointer to underlying XFS inode
- `vfs_inode` — embedded VFS inode (must be last for `container_of`)

### Dentry Private Data (mxfs_dentry_info)

- `lower_path` — dentry+vfsmount of the lower XFS dentry

### File Private Data (mxfs_file_info)

- `lower_file` — pointer to underlying XFS file struct

## mxfs_netlink.c — Implementation Details

### Genetlink Family
- Registers family name "mxfs" version 1 via `genl_register_family()`
- Defines attribute policy for all `MXFS_NL_ATTR_*` types including UUID and DAEMON_PID
- Two multicast groups: "locks" and "status"

### Operations Table
All `MXFS_NL_CMD_*` commands are registered:
- **LOCK_REQ** / **LOCK_RELEASE** — kernel-originated, sent via helpers
- **LOCK_GRANT** — daemon sends grant; handler completes the pending request
- **LOCK_DENY** — daemon denies; handler completes with error status
- **CACHE_INVAL** — daemon requests page cache invalidation; delegates to `mxfs_cache_invalidate()`
- **NODE_STATUS** — daemon reports node state changes; stored in `node_states[]`
- **VOLUME_MOUNT** / **VOLUME_UMOUNT** — volume lifecycle notifications
- **STATUS_REQ** / **STATUS_RESP** — daemon registration handshake
- **RECOVERY_START** / **RECOVERY_DONE** — per-SBI recovery state via `mxfs_cache_find_sbi_by_volume()`
- **DAEMON_READY** — daemon signals readiness; sets portid/pid on SBI, completes `daemon_startup`

### Per-Mount Portid
- No global daemon_portid — each mount tracks its own `sbi->daemon_portid`
- Lock send functions look up SBI via `mxfs_cache_find_sbi_by_volume(resource->volume)`
- Supports multiple concurrent mounts (multiple volumes, multiple daemons)

### Pending Lock Requests
- 256-bucket hash table keyed on `mxfs_resource_id`
- Each pending request has a `struct completion` for blocking the caller
- `mxfs_nl_send_lock_req()` inserts into hash, sends message, blocks with 30s timeout
- On grant/deny, handler looks up by resource and calls `complete()`

## mxfs_cache.c — Implementation Details

### Volume-to-Superblock Mapping
- 16-bucket hash table mapping volume IDs to `struct super_block *`
- `mxfs_cache_register_sb()` — register on mount
- `mxfs_cache_unregister_sb()` — unregister on unmount
- `mxfs_cache_find_sbi_by_volume()` — lookup SBI by volume_id (used by netlink handlers)

### Invalidation
- `mxfs_cache_invalidate(volume, ino, offset, length)` — main entry point
- Looks up superblock from volume ID, finds inode via `ilookup()`
- If inode not in icache, returns 0 (nothing to invalidate)
- If length=0, calls `invalidate_inode_pages2()` for full invalidation
- Otherwise calls `invalidate_inode_pages2_range()` for partial range

## mxfs_main.c — Implementation Details

### Initialization Order
1. `mxfs_init_inode_cache()` — SLAB cache for mxfs_inode_info
2. `mxfs_netlink_init()` — register genetlink family
3. `mxfs_cache_init()` — initialize page cache invalidation subsystem
4. `register_filesystem(&mxfs_fs_type)` — register "mxfs" filesystem type

### Error Rollback
If any init step fails, previously initialized subsystems are torn down in reverse.

### Shutdown Order (reverse of init)
1. `unregister_filesystem(&mxfs_fs_type)`
2. `mxfs_cache_exit()`
3. `mxfs_netlink_exit()`
4. `mxfs_destroy_inode_cache()`

### Module Metadata
- License: GPL
- Version: 1.0.0 (tracked in MODULE_VERSION)
- Prints version from MXFS_VERSION_MAJOR/MINOR/PATCH on load

## Version History

- 0.1.0 — Initial project structure, stub implementations
- 0.2.0 — Implemented mxfs_netlink.c: genetlink family, ops, pending lock tracking
- 0.3.0 — Implemented mxfs_hooks.c: XFS kprobe-based lock intercepts
- 0.4.0 — Implemented mxfs_cache.c + mxfs_main.c: cache invalidation, module wiring
- 1.0.0 — Stacking filesystem refactor: replaced kprobe hooks with proper VFS
  stacking (like ecryptfs/overlayfs). New files: mxfs_super.c (mount/unmount,
  daemon lifecycle), mxfs_inode.c (inode ops with DLM locks), mxfs_file.c
  (file ops with DLM locks), mxfs_dir.c (directory ops with DLM locks).
  Deleted mxfs_hooks.c. Rewrote mxfs_internal.h with stacking data structures.
  Rewrote mxfs_main.c for filesystem registration. Updated mxfs_netlink.c
  with DAEMON_READY handler, per-mount portid, per-SBI recovery state.
  Updated mxfs_cache.c with mxfs_cache_find_sbi_by_volume(). User experience:
  `mount -t mxfs /dev/sdb /mnt/shared` — zero config, daemon auto-spawned.
