# MXFS Refactor — Stacking Filesystem Architecture

## Purpose of This Document

This document contains everything needed to refactor MXFS from a kprobe-based
hook system with a standalone daemon into a proper stacking filesystem. A new
agent session should read this file, then read `INFO.md` and `TASKS.md` for
full project context before starting work.

## Why This Refactor

The current architecture has two fatal problems:

1. **Lockstate file requires a mounted filesystem** — The on-disk lock
   persistence layer (`.mxfs/lockstate`) is a file on the XFS volume. But
   the daemon starts before the volume is mounted. The lockstate file can't
   be opened until after mount, but locks need to be in place before mount.
   Chicken-and-egg.

2. **Kprobes are fragile** — The current kernel module uses kprobes to hook
   XFS internal functions. These break across kernel versions when XFS
   internals change. A proper filesystem type registration is stable.

## Target Architecture

Replace the kprobe-based `mxfs.ko` + standalone `mxfsd` with:

- **mxfs.ko** — A stacking filesystem (like ecryptfs/overlayfs) that
  registers filesystem type `mxfs`. On `mount -t mxfs`, it internally
  mounts XFS, spawns the daemon, and sets up the entire lock infrastructure.

- **mxfsd** — Same daemon code, but lifecycle is controlled by mount/unmount
  instead of a CLI. No more `start`/`stop`/`status` commands. The kernel
  module spawns it via `call_usermodehelper()` and kills it on unmount.

### Target User Experience

```bash
mkfs.xfs /dev/sdb                         # standard XFS — nothing custom
mount -t mxfs /dev/sdb /mnt/shared        # everything starts automatically
# ... use the filesystem ...
umount /mnt/shared                         # everything stops automatically
```

No config files. No manual daemon management. No separate start/stop.

### Mount Sequence (What Happens Inside `mount -t mxfs`)

```
1. VFS calls mxfs.ko's mount handler (mxfs_mount / mxfs_fill_super)
2. mxfs.ko calls vfs_kern_mount() to mount XFS internally on the device
3. mxfs.ko reads XFS sb_uuid from the underlying superblock
4. mxfs.ko spawns mxfsd via call_usermodehelper():
     /usr/sbin/mxfsd --device /dev/sdb --mountpoint /mnt/shared --uuid <sb_uuid>
5. mxfsd starts:
   a. SCSI-3 PR register + reserve (raw device, works before any file I/O)
   b. Open/create .mxfs/lockstate on the now-mounted filesystem
   c. Start disklock heartbeat
   d. Start UDP discovery (multicast)
   e. Start TCP DLM, connect to discovered peers
   f. Signal readiness back to kernel via netlink
6. mxfs.ko receives readiness signal, completes the mount
7. User's mount command returns — filesystem is clustered and ready
```

### Unmount Sequence

```
1. VFS calls mxfs.ko's umount handler
2. mxfs.ko sends SIGTERM to mxfsd via netlink or direct signal
3. mxfsd shuts down:
   a. Release all DLM locks
   b. Stop discovery
   c. Disconnect peers
   d. Stop disklock heartbeat, close lockstate file
   e. SCSI PR unregister
   f. Exit
4. mxfs.ko unmounts the underlying XFS
5. Unmount complete
```

### Why This Fixes the Lockstate Problem

The kernel module mounts XFS *first* (step 2), *then* spawns the daemon
(step 4). By the time the daemon needs to open `.mxfs/lockstate`, the
filesystem is already mounted. The lockstate file is always accessible
because mxfs.ko guarantees the mount order.

## What Changes

### Kernel Module — FULL REWRITE

The current kernel module (1336 lines across 4 files) is kprobe-based and
needs to become a stacking filesystem. This is the bulk of the work.

**Current files to rewrite:**
- `kernel/mxfs_main.c` (81 lines) — becomes filesystem registration + mount/umount
- `kernel/mxfs_hooks.c` (279 lines) — becomes VFS operation wrappers
- `kernel/mxfs_netlink.c` (610 lines) — mostly stays, add daemon lifecycle
- `kernel/mxfs_cache.c` (182 lines) — stays mostly the same
- `kernel/mxfs_internal.h` (55 lines) — updated for new architecture

**New kernel architecture:**

```
kernel/
├── mxfs_main.c       — module_init/exit, register_filesystem("mxfs")
├── mxfs_super.c      — mount/umount, fill_super, spawn/kill daemon
├── mxfs_inode.c      — inode_operations: create, lookup, unlink, mkdir, etc.
│                        Each op: acquire DLM lock → delegate to XFS → release
├── mxfs_file.c       — file_operations: read, write, mmap, fsync, etc.
│                        Each op: acquire DLM lock → delegate to XFS → release
├── mxfs_dir.c        — dir inode_operations + file_operations for directories
├── mxfs_netlink.c    — genetlink (mostly same, add daemon spawn/signal)
├── mxfs_cache.c      — page cache invalidation (same as current)
└── mxfs_internal.h   — internal declarations
```

**Key kernel concepts:**

The stacking approach stores a pointer to the underlying XFS inode/dentry
in each mxfs inode/dentry's private data. Every VFS operation:
1. Extracts the underlying XFS object
2. Acquires DLM lock via netlink to mxfsd
3. Calls the underlying XFS operation
4. Releases the DLM lock
5. Returns the result

This is the same pattern used by ecryptfs and wrapfs.

**Superblock private data:**
```c
struct mxfs_sb_info {
    struct super_block *lower_sb;       /* underlying XFS superblock */
    struct vfsmount    *lower_mnt;      /* underlying XFS mount */
    uint8_t             volume_uuid[16]; /* XFS sb_uuid */
    mxfs_volume_id_t    volume_id;      /* derived from UUID */
    pid_t               daemon_pid;     /* mxfsd process */
    uint32_t            daemon_portid;  /* netlink port */
    bool                daemon_ready;   /* daemon signaled ready */
    struct completion    daemon_startup; /* wait for daemon ready */
};
```

**Inode private data:**
```c
struct mxfs_inode_info {
    struct inode *lower_inode;  /* underlying XFS inode */
};
```

### Daemon — MODERATE CHANGES

The daemon subsystems are mostly fine. What changes:

**Remove entirely:**
- CLI parsing (start/stop/status, getopt_long)
- Daemonization (fork, setsid, PID file)
- Config file mode (--config, INI parser)
- SIGHUP reload logic
- Usage/help text

**Change:**
- `mxfsd_main.c` — Rewrite. Daemon receives device, mountpoint, UUID as
  command-line args from `call_usermodehelper()`. No CLI commands, no
  daemonization (the kernel handles the process lifecycle). Simplified
  startup: parse args → init subsystems → signal ready → main loop.
- The daemon becomes: `/usr/sbin/mxfsd --device /dev/sdb --mountpoint /mnt/shared --uuid <hex>`

**Keep as-is (no changes needed):**
- `mxfsd_dlm.c/h` — DLM engine, distributed mastering, lock table
- `mxfsd_peer.c/h` — TCP peer connections, message framing
- `mxfsd_discovery.c/h` — UDP multicast/broadcast peer discovery
- `mxfsd_scsi_pr.c/h` — SCSI-3 Persistent Reservations
- `mxfsd_disklock.c/h` — On-disk lock state persistence
- `mxfsd_netlink.c/h` — Genetlink communication with kernel
- `mxfsd_lease.c/h` — Lease-based node liveness
- `mxfsd_journal.c/h` — Journal recovery coordination
- `mxfsd_log.c/h` — Logging
- `mxfsd_volume.c/h` — Volume state tracking

**Can probably remove:**
- `mxfsd_config.c/h` — INI config parser (no more config files)
  Keep only if we want optional config override for non-default ports, etc.

### Shared Headers — MINOR CHANGES

- `include/mxfs/mxfs_common.h` — Version bump, maybe add mount options struct
- `include/mxfs/mxfs_netlink.h` — Add DAEMON_READY command, add
  DAEMON_SPAWN attrs (device path, mount point, UUID)
- `include/mxfs/mxfs_dlm.h` — No changes needed

### Build — UPDATE

- `kernel/Makefile` — Add new source files (mxfs_super.c, mxfs_inode.c,
  mxfs_file.c, mxfs_dir.c), remove mxfs_hooks.c
- `daemon/Makefile` — Possibly remove mxfsd_config.o if config is dropped
- Install target should put mxfsd at `/usr/sbin/mxfsd`

## Three-Layer Fencing Architecture (PRESERVE)

This was implemented in v0.4.0 and must be preserved exactly:

1. **SCSI-3 PR** (Layer 1 — hardware) — WRITE EXCLUSIVE REGISTRANTS ONLY.
   Register key = node_id. On node death, survivors PREEMPT the dead node's
   key. Storage array rejects all further I/O from the fenced node. Zero
   cost on lock hot path. Code: `daemon/mxfsd_scsi_pr.c/h`

2. **On-disk lockstate** (Layer 2 — persistent) — `.mxfs/lockstate` file.
   O_DIRECT + O_SYNC, 512-byte sector-aligned records. 64 heartbeat slots
   + 65536 lock record slots. Every lock grant written to disk before
   response. Every release clears the record. Heartbeat every 2 seconds.
   Code: `daemon/mxfsd_disklock.c/h`

3. **TCP DLM** (Layer 3 — performance) — In-memory lock negotiation.
   Distributed per-resource mastering via FNV-1a hash. Fast path for
   uncontested locks. Code: `daemon/mxfsd_dlm.c/h`

Fencing sequence on node death:
1. SCSI PREEMPT → hardware blocks dead node's I/O
2. Disk purge → clear dead node's lock records
3. Memory purge → clear in-memory DLM state, promote waiters
4. Journal recovery → replay dead node's XFS log

## Discovery System (PRESERVE)

Implemented in v0.5.0. UDP multicast peer discovery, zero config:

- Default multicast group: 239.66.83.1 port 7601
- Announcement packet: node UUID, node ID, TCP port, volume UUID, hostname
- Volume UUID read from XFS superblock (sb_uuid at offset 32)
- Nodes sharing same volume UUID auto-form lock group
- After discovery, TCP connections established for DLM traffic
- Code: `daemon/mxfsd_discovery.c/h`

## Current File Inventory

### Shared Headers
- `include/mxfs/mxfs_common.h` — types, constants, error codes (v0.5.1)
- `include/mxfs/mxfs_dlm.h` — DLM protocol, lock modes, message formats
- `include/mxfs/mxfs_netlink.h` — genetlink commands and attributes

### Daemon (all compile clean with -Wall -Wextra -Werror)
- `daemon/mxfsd_main.c` (1830 lines) — **REWRITE** (remove CLI, simplify)
- `daemon/mxfsd_config.c/h` — **MAYBE REMOVE** (no more config files)
- `daemon/mxfsd_dlm.c/h` (775/105 lines) — keep
- `daemon/mxfsd_peer.c/h` (753/91 lines) — keep
- `daemon/mxfsd_discovery.c/h` (508/95 lines) — keep
- `daemon/mxfsd_scsi_pr.c/h` (~500/60 lines) — keep
- `daemon/mxfsd_disklock.c/h` (~550/90 lines) — keep
- `daemon/mxfsd_netlink.c/h` — keep
- `daemon/mxfsd_lease.c/h` — keep
- `daemon/mxfsd_journal.c/h` — keep
- `daemon/mxfsd_log.c/h` — keep
- `daemon/mxfsd_volume.c/h` — keep

### Kernel Module (currently 1336 lines — FULL REWRITE)
- `kernel/mxfs_main.c` (81 lines) — rewrite: filesystem registration
- `kernel/mxfs_hooks.c` (279 lines) — replace with mxfs_inode.c/mxfs_file.c/mxfs_dir.c
- `kernel/mxfs_netlink.c` (610 lines) — keep/extend: add daemon lifecycle
- `kernel/mxfs_cache.c` (182 lines) — keep
- `kernel/mxfs_internal.h` (55 lines) — rewrite for new architecture
- NEW: `kernel/mxfs_super.c` — mount/umount, fill_super, daemon spawn
- NEW: `kernel/mxfs_inode.c` — inode operations with DLM locking
- NEW: `kernel/mxfs_file.c` — file operations with DLM locking
- NEW: `kernel/mxfs_dir.c` — directory operations with DLM locking

## Implementation Order

### Phase 1: Kernel Module Stacking Filesystem

1. **mxfs_super.c** — `register_filesystem()`, `mount`/`kill_sb`,
   `fill_super` that mounts XFS underneath, `mxfs_sb_info` allocation.
   Start with just mounting XFS — no daemon spawn yet.

2. **mxfs_inode.c** — Inode operations that delegate to underlying XFS.
   Start as pure passthrough (no locking), then add DLM lock calls.
   Key ops: `lookup`, `create`, `unlink`, `mkdir`, `rmdir`, `rename`,
   `permission`, `getattr`, `setattr`.

3. **mxfs_file.c** — File operations that delegate to underlying XFS.
   Start as pure passthrough, then add DLM locks.
   Key ops: `read_iter`, `write_iter`, `open`, `release`, `fsync`, `mmap`.

4. **mxfs_dir.c** — Directory iteration. `iterate_shared` / `readdir`
   delegating to XFS.

5. **mxfs_main.c** — Module init/exit wiring.

6. **mxfs_internal.h** — New data structures (`mxfs_sb_info`,
   `mxfs_inode_info`, helper macros to get lower inode/sb).

### Phase 2: Daemon Lifecycle Integration

7. **mxfs_super.c additions** — Add `call_usermodehelper()` to spawn mxfsd
   during mount, `kill_pid()` during unmount. Wait for daemon ready signal
   via completion.

8. **mxfs_netlink.c updates** — Add `MXFS_NL_CMD_DAEMON_READY` command.
   Add attrs for device path, mount point, UUID.

9. **mxfsd_main.c rewrite** — Strip CLI, accept args from kernel
   (`--device`, `--mountpoint`, `--uuid`). Init subsystems, signal ready
   via netlink, run main loop, clean shutdown on SIGTERM.

### Phase 3: DLM Lock Integration

10. **Add DLM lock calls** to inode/file/dir operations. Each VFS op wraps
    the underlying XFS call with lock acquire/release via netlink to mxfsd.

11. **Wire cache invalidation** — On BAST (blocking AST), mxfsd sends
    CACHE_INVAL via netlink, kernel invalidates pages, daemon downcoverts
    lock.

### Phase 4: Testing

12. Compile kernel module against target kernel headers.
13. Compile daemon.
14. Test on 2-node cluster (192.168.120.28 and 192.168.120.201, root/see
    passfile at /tmp/.mxfs_pass, source deployed to /root/mxfs).
15. Verify: mount on both nodes, write on one, read on other, unmount clean.

## Test Nodes

- **192.168.120.28** — Debian 11, kernel 5.10.0-37-amd64
- **192.168.120.201** — Debian 11, kernel 5.10.0-30-amd64
- Root access via password (use expect with passfile /tmp/.mxfs_pass)
- Shared block device: `/dev/sdb` (XFS formatted)
- Source deployed to `/root/mxfs` on both nodes
- Deploy script: `/tmp/mxfs_deploy.sh` (uses `/tmp/mxfs_ssh.exp`)

## Key Design Decisions

- **Disk format is standard XFS** — `mkfs.xfs` only. No custom on-disk
  metadata. The `.mxfs/` directory is created at runtime by the daemon.
- **Stacking, not modifying XFS** — We don't patch XFS source. We wrap it
  at the VFS layer.
- **Daemon per mount** — Each `mount -t mxfs` spawns one mxfsd instance
  for that volume. Multiple volumes = multiple daemons.
- **No config files** — The common case requires zero configuration.
- **Node identity** — Persistent UUID at `/etc/mxfs/node.uuid`, generated
  on first run. Node ID derived via FNV-1a hash.
- **DLM port** — TCP 7600 (DLM traffic), UDP 7601 (discovery).

## Version

Current: 0.5.1. Bump to 1.0.0 for this refactor (major architectural change).

## Critical Rules

- No git commands
- No mock/fake data
- No underscore suffix on variable names
- No temp files in project dir (use /tmp)
- Rev version: patch for fixes, minor for features, major for major changes
- Maintain .md files for each module after changes
- Build must compile clean with -Wall -Wextra -Werror (daemon)
- Do not edit the Makefile without being told to do so
