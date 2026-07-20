# MXFS Architecture — Cross-Platform Clustered Filesystem

## Vision

A high-performance cross-platform clustered filesystem that allows Linux, macOS, Windows, and ARM Linux (Raspberry Pi) nodes to concurrently mount and share a single XFS-formatted block device (iSCSI LUN, FC, NVMe-oF) with full read/write access on every node.

## Design

MXFS uses a **native XFS format I/O engine** — it reads and writes XFS on-disk structures directly, with its own DLM-aware caching at every layer. When a BAST fires, MXFS can flush and invalidate any cached data because it owns every cache.

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                    libmxfs (portable C)               │
│                                                      │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐ │
│  │  XFS    │ │  DLM    │ │  Cache  │ │  Cluster  │ │
│  │  Format │ │  Engine │ │  Layer  │ │  Services │ │
│  │  I/O    │ │         │ │ (block, │ │ (peer,    │ │
│  │         │ │         │ │  inode, │ │  discover,│ │
│  │         │ │         │ │  dir)   │ │  lease,   │ │
│  │         │ │         │ │         │ │  fence,   │ │
│  │         │ │         │ │         │ │  journal) │ │
│  └────┬────┘ └────┬────┘ └────┬────┘ └─────┬─────┘ │
│       │           │           │             │       │
│  ┌────▼───────────▼───────────▼─────────────▼─────┐ │
│  │         Platform Abstraction Layer (PAL)        │ │
│  │   block I/O, threads, sockets, memory, time     │ │
│  └─────────────────────┬───────────────────────────┘ │
└────────────────────────┼─────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
   ┌──────▼──────┐ ┌────▼─────┐ ┌──────▼──────┐
   │  mxfs.ko    │ │ mxfs-    │ │ mxfs-       │
   │  Linux VFS  │ │ fskit    │ │ winfsp      │
   │  kernel mod │ │ macOS    │ │ Windows     │
   └─────────────┘ └──────────┘ └─────────────┘
```

## Proven Components

These components are proven and carry forward from earlier designs:

| Component | Status | Notes |
|-----------|--------|----------------|
| DLM wire protocol | Keep as-is | Same message formats, same mastering |
| Discovery protocol | Keep as-is | Same UDP multicast, same announce format |
| Lease protocol | Keep as-is | Same timing, same state machine |
| Lock modes & resource IDs | Keep as-is | Add LTYPE_AG resource usage |
| Three-layer fencing | Keep, adapt | SCSI PR via PAL, disklock via PAL |
| Per-node journal coordination | Keep as-is | Same slot claiming, same recovery flow |
| Disklock on-disk format | Keep as-is | Same heartbeat/lock record layout |
| Node UUID / node ID derivation | Keep as-is | Same FNV-1a hash |
| Volume ID derivation | Keep as-is | Same FNV-1a of XFS sb_uuid |

## Design Decisions (vs stacking approach)

| Stacking FS | MXFS (Native I/O) |
|----------------|------------------|
| Mount XFS via `vfs_kern_mount()`, wrap at VFS layer | Read/write XFS on-disk format directly |
| XFS owns block cache (`xfs_buf`) | libmxfs owns block cache, DLM-aware |
| XFS owns inode cache (`xfs_inode`) | libmxfs owns inode cache, DLM-aware |
| XFS owns directory parsing | libmxfs parses XFS dir format directly |
| XFS owns allocation (inobt, AGF, AGI) | libmxfs manages allocation, AG-level DLM locks |
| Linux-only kernel module | Portable C library + platform frontends |
| BAST tries to invalidate XFS caches externally | BAST flushes and drops our own caches directly |
| `sync_filesystem()` for flush | Direct writeback of dirty blocks we track |

## Core Library: libmxfs

### XFS Format I/O Engine

Reads and writes XFS on-disk structures directly. No dependency on Linux XFS code.

**Superblock**: Parse `xfs_sb` to get geometry (block size, AG count/size, inode size, root ino, journal location, feature flags).

**Allocation Groups**: Each AG has AGF (free space), AGI (inode allocation), AGFL (free list). Parse B+ tree structures (bnobt, cntbt, inobt, finobt) for block and inode allocation.

**Inodes**: Read/write `xfs_dinode` (v3 with CRC). Parse data fork (inline, extents, btree) and attr fork. Handle all directory formats (shortform, block, leaf, node/btree).

**Directories**: Parse all four XFS directory formats:
- Shortform (inline in inode data fork, < ~300 bytes)
- Block (single directory block with header + entries)
- Leaf (data blocks + single leaf block with hash index)
- Node/Btree (data blocks + multi-level hash index tree)

**Extent mapping**: Parse extent lists and B+ tree extent maps to translate logical file offsets to physical disk blocks.

**Journal**: Read/write XFS log format for crash recovery. Each node writes to its own log area (partitioned by node slot). On BAST-triggered lock release, flush dirty metadata through the journal before dropping the lock. On node failure, another node replays the dead node's journal.

### DLM-Aware Cache Layer

Three cache tiers, all integrated with the DLM:

**Block Cache** (replaces `xfs_buf`):
- Cache disk blocks by (device, block_number)
- Each cached block tracks: data, dirty flag, DLM lock reference, pin count
- On BAST: write dirty blocks to disk, then drop from cache
- LRU eviction for memory pressure
- Write coalescing for adjacent dirty blocks

**Inode Cache**:
- Cache parsed inodes by inode number
- Stores: dinode core fields, extent map, data fork contents (for inline dirs)
- Each cached inode holds a DLM INODE lock
- On BAST: flush dirty inode fields to disk block via block cache, drop inode from cache
- VFS inode (or platform equivalent) points to cached libmxfs inode

**Directory Cache**:
- Cache directory entries (name → ino mapping) per directory inode
- Populated on readdir or lookup, invalidated on BAST
- Create/unlink/rename update cache locally, mark dirty, flush on lock release

### DLM Lock Integration

Every I/O path acquires appropriate DLM locks:

```
readdir(dir):
    acquire PR lock on dir inode
    if cache miss: read dir blocks from disk, populate dir cache
    return cached entries
    release lock (keep cached until BAST)

create(dir, name):
    acquire EX lock on dir inode
    acquire EX lock on AG (for inode allocation)
    allocate inode from inobt
    add directory entry
    mark dir blocks + inobt + AGI dirty
    release locks (flush dirty blocks first)

read(file, offset, len):
    acquire PR lock on file inode
    map logical offset → physical blocks via extent map
    read data blocks (from block cache or disk)
    release lock

write(file, offset, len):
    acquire EX lock on file inode
    acquire EX lock on AG (if allocating new extents)
    allocate blocks if needed
    write data to block cache (dirty)
    update extent map
    release locks (flush dirty blocks first)
```

### AG Affinity for Performance

Each node preferentially allocates from a subset of AGs to minimize contention:

- On mount, node claims preferred AGs: `preferred_ag = node_slot % ag_count` as starting point
- Inode and block allocation tries preferred AGs first
- Falls back to other AGs only when preferred AGs are full
- AG lock (LTYPE_AG, EX mode) held only during allocation, not during read/write
- Result: nodes working on different files rarely contend on AG locks

### BAST Flush Sequence

When a BAST fires (another node needs a conflicting lock):

1. Wait for active holders to drain (bounded timeout)
2. Write all dirty blocks associated with this resource to disk
3. Ensure journal entry is committed (write-ahead)
4. Drop cached data for this resource (block cache entries, inode, dir entries)
5. Release the DLM lock
6. Signal the DLM to grant to the requesting node

This is the key correctness property: **no lock is released until all dirty data for that resource is on disk and all cached data is dropped**.

## Platform Abstraction Layer (PAL)

Thin layer providing OS-specific primitives to libmxfs:

```c
/* Block device I/O */
mxfs_bdev_t *mxfs_pal_bdev_open(const char *path);
void         mxfs_pal_bdev_close(mxfs_bdev_t *dev);
int          mxfs_pal_bdev_read(mxfs_bdev_t *dev, uint64_t offset, void *buf, uint32_t len);
int          mxfs_pal_bdev_write(mxfs_bdev_t *dev, uint64_t offset, const void *buf, uint32_t len);
int          mxfs_pal_bdev_flush(mxfs_bdev_t *dev);

/* Threading */
mxfs_thread_t *mxfs_pal_thread_create(void (*fn)(void *), void *arg);
void           mxfs_pal_thread_join(mxfs_thread_t *t);
void           mxfs_pal_mutex_lock(mxfs_mutex_t *m);
void           mxfs_pal_mutex_unlock(mxfs_mutex_t *m);
void           mxfs_pal_condvar_wait(mxfs_cond_t *c, mxfs_mutex_t *m);
void           mxfs_pal_condvar_signal(mxfs_cond_t *c);

/* Networking */
mxfs_sock_t *mxfs_pal_tcp_connect(const char *host, uint16_t port);
mxfs_sock_t *mxfs_pal_tcp_listen(uint16_t port);
mxfs_sock_t *mxfs_pal_tcp_accept(mxfs_sock_t *listener);
int          mxfs_pal_tcp_send(mxfs_sock_t *s, const void *buf, uint32_t len);
int          mxfs_pal_tcp_recv(mxfs_sock_t *s, void *buf, uint32_t len);
mxfs_sock_t *mxfs_pal_udp_open(uint16_t port);
int          mxfs_pal_udp_sendto(mxfs_sock_t *s, const void *buf, uint32_t len, const char *host, uint16_t port);
int          mxfs_pal_udp_recvfrom(mxfs_sock_t *s, void *buf, uint32_t len, char *from_host, uint16_t *from_port);
int          mxfs_pal_udp_join_multicast(mxfs_sock_t *s, const char *group);

/* Memory */
void *mxfs_pal_alloc(size_t size);
void  mxfs_pal_free(void *ptr);

/* Time */
uint64_t mxfs_pal_time_ms(void);  /* monotonic milliseconds */

/* Logging */
void mxfs_pal_log(int level, const char *fmt, ...);

/* SCSI PR (optional, for hardware fencing) */
int mxfs_pal_scsi_pr_register(mxfs_bdev_t *dev, uint64_t key);
int mxfs_pal_scsi_pr_reserve(mxfs_bdev_t *dev, uint64_t key);
int mxfs_pal_scsi_pr_preempt(mxfs_bdev_t *dev, uint64_t my_key, uint64_t victim_key);
```

### PAL Implementations

| Platform | Block I/O | Threads | Sockets | SCSI PR |
|----------|-----------|---------|---------|---------|
| Linux kernel | bio/bdev | kthread | kernel_socket | pr_ops |
| Linux userspace | O_DIRECT fd | pthreads | POSIX sockets | SG_IO ioctl |
| macOS FSKit | IOKit disk | pthreads | POSIX sockets | SG_IO ioctl |
| Windows | CreateFile DIRECT | Win32 threads | Winsock | SCSI passthrough |

## Platform Frontends

### Linux Kernel Module (mxfs.ko)

Registers filesystem type "mxfs" with Linux VFS. Translates VFS operations to libmxfs calls:

- `inode_operations.create` → `mxfs_create()` → libmxfs
- `inode_operations.lookup` → `mxfs_lookup()` → libmxfs
- `file_operations.read_iter` → `mxfs_read()` → libmxfs
- `file_operations.write_iter` → `mxfs_write()` → libmxfs
- `file_operations.iterate_shared` → `mxfs_readdir()` → libmxfs

PAL implemented via kernel APIs (bio, kthread, kernel sockets). Maximum performance, zero context switches.

### macOS FSKit Extension

FSKit (macOS 15+) provides `FSFileSystem`, `FSVolume`, `FSFile`, `FSDirectory` delegates. Runs as a signed system extension.

- `FSVolume.mount()` → libmxfs mount
- `FSDirectory.lookup()` → libmxfs lookup
- `FSFile.read()` → libmxfs read
- `FSFile.write()` → libmxfs write
- `FSDirectory.enumerate()` → libmxfs readdir

PAL implemented via POSIX APIs (pthreads, sockets) + IOKit for raw disk access. Requires Apple Developer signing.

### Windows WinFsp Driver

WinFsp provides a kernel-mode filesystem interface with a userspace service. MXFS implements the WinFsp `FSP_FILE_SYSTEM_INTERFACE`:

- `Open` → libmxfs open
- `Read` → libmxfs read
- `Write` → libmxfs write
- `ReadDirectory` → libmxfs readdir
- `Create` → libmxfs create

PAL implemented via Win32 APIs (CreateFile with FILE_FLAG_NO_BUFFERING, Win32 threads, Winsock).

## Implementation Phases

### Phase 1: Portable Core Library (libmxfs)

Build and test in userspace on Linux. No kernel module yet.

1. **PAL — Linux userspace implementation** (pthreads, POSIX sockets, O_DIRECT)
2. **XFS superblock reader** — parse geometry from raw device
3. **Block cache** — read/write/dirty/flush/evict with LRU
4. **XFS inode reader** — parse dinode, extent maps, data fork
5. **XFS directory reader** — all four formats (shortform, block, leaf, node)
6. **Read-only mount** — mount, readdir, stat, read file contents
7. **DLM engine** — port from v1 kernel code to portable C
8. **Peer networking** — port TCP mesh from v1
9. **Discovery** — port UDP multicast from v1
10. **Leases** — port from v1
11. **DLM integration into cache** — lock acquisition on read paths, BAST flush/drop
12. **Write path** — directory entry creation, inode allocation, block allocation
13. **Journal** — write-ahead logging, crash recovery
14. **Disklock** — port from v1
15. **SCSI PR fencing** — port from v1 via PAL

### Phase 2: Linux Kernel Frontend

16. **PAL — Linux kernel implementation** (bio, kthread, kernel sockets)
17. **VFS integration** — register filesystem, implement inode/file/dir operations
18. **Testing** — multi-node concurrent I/O on test cluster

### Phase 3: macOS Frontend

19. **PAL — macOS implementation** (IOKit, pthreads, POSIX sockets)
20. **FSKit integration** — FSVolume/FSFile/FSDirectory delegates
21. **Code signing** — Apple Developer certificate
22. **Testing** — Mac + Linux nodes sharing iSCSI LUN

### Phase 4: Windows Frontend

23. **PAL — Windows implementation** (Win32 APIs, Winsock)
24. **WinFsp integration** — filesystem interface implementation
25. **Testing** — Windows + Linux + Mac all sharing same LUN

## Directory Structure

```
mxfs/
├── libmxfs/              # Portable core library
│   ├── xfs_format.c/h    # XFS on-disk format parsing
│   ├── block_cache.c/h   # DLM-aware block cache
│   ├── inode_cache.c/h   # DLM-aware inode cache
│   ├── dir_cache.c/h     # DLM-aware directory cache
│   ├── alloc.c/h         # Block and inode allocation
│   ├── extent.c/h        # Extent map parsing and management
│   ├── journal.c/h       # Write-ahead log
│   ├── dlm.c/h           # DLM engine
│   ├── peer.c/h          # TCP peer connections
│   ├── discovery.c/h     # UDP multicast discovery
│   ├── lease.c/h         # Node liveness
│   ├── disklock.c/h      # On-disk lock persistence
│   ├── scsipr.c/h        # SCSI PR fencing (via PAL)
│   ├── mount.c/h         # Mount/unmount orchestration
│   └── mxfs.h            # Public API for frontends
├── pal/                   # Platform abstraction layer
│   ├── pal.h             # PAL interface
│   ├── pal_linux_user.c  # Linux userspace (development)
│   ├── pal_linux_kern.c  # Linux kernel
│   ├── pal_macos.c       # macOS (FSKit/IOKit)
│   └── pal_windows.c     # Windows (Win32)
├── frontend/
│   ├── linux/            # mxfs.ko — Linux VFS integration
│   ├── macos/            # FSKit system extension
│   └── windows/          # WinFsp filesystem driver
├── tools/
│   ├── mxfs_deploy.sh
│   ├── mxfs_bench.sh
│   └── mxfs_test.c       # Userspace test harness
├── include/mxfs/
│   ├── mxfs_common.h     # Shared types (kept from v1)
│   └── mxfs_dlm.h        # DLM protocol (kept from v1)
└── docs/
    ├── architecture.md   # This document
    ├── dlm-protocol.md    # Wire protocol spec (kept from v1)
    └── xfs-format.md      # XFS on-disk format reference
```

## Code Origin Map

Historical record of where each module originated:

### Kept as-is (protocol definitions)
| Origin | Current File | Notes |
|---------|---------|-------|
| `include/mxfs/mxfs_common.h` | `include/mxfs/mxfs_common.h` | Types, enums, FNV-1a — unchanged |
| `include/mxfs/mxfs_dlm.h` | `include/mxfs/mxfs_dlm.h` | Wire protocol structs — unchanged |
| `docs/dlm-protocol.md` | `docs/dlm-protocol.md` | Protocol spec — unchanged |

### Ported from kernel C to portable C
| Origin | Current File | Changes Made |
|---------|---------|----------------|
| `kernel/mxfs_dlm.c` (~1100 lines) | `libmxfs/dlm.c` | Replace kmalloc→mxfs_pal_alloc, kthread→mxfs_pal_thread, kernel_sendmsg→mxfs_pal_tcp_send, spinlock→mxfs_pal_mutex. Core DLM logic (lock table, mastering, BAST, grant queue) stays identical. |
| `kernel/mxfs_dlm.h` | `libmxfs/dlm.h` | Remove linux headers, use PAL types |
| `kernel/mxfs_peer.c` (~550 lines) | `libmxfs/peer.c` | Replace kernel_socket→mxfs_pal_tcp_*, kthread→mxfs_pal_thread. TCP framing, message dispatch, lower-ID-initiates rule stay identical. |
| `kernel/mxfs_peer.h` | `libmxfs/peer.h` | Remove linux headers |
| `kernel/mxfs_discovery.c` (~350 lines) | `libmxfs/discovery.c` | Replace kernel UDP→mxfs_pal_udp_*, delayed_work→mxfs_pal_thread+sleep. Multicast announce/receive logic stays identical. |
| `kernel/mxfs_discovery.h` | `libmxfs/discovery.h` | Remove linux headers |
| `kernel/mxfs_lease.c` (~320 lines) | `libmxfs/lease.c` | Replace delayed_work→mxfs_pal_thread, jiffies→mxfs_pal_time_ms. State machine and timing logic stay identical. |
| `kernel/mxfs_lease.h` | `libmxfs/lease.h` | Remove linux headers |
| `kernel/mxfs_disklock.c` (~480 lines) | `libmxfs/disklock.c` | Replace filp_open/kernel_write→mxfs_pal_bdev_read/write. Record format and slot logic stay identical. |
| `kernel/mxfs_disklock.h` | `libmxfs/disklock.h` | Remove linux headers |
| `kernel/mxfs_scsipr.c` (~210 lines) | `libmxfs/scsipr.c` | Replace pr_ops→mxfs_pal_scsi_pr_*. Registration/reservation/preempt logic stays identical. |
| `kernel/mxfs_scsipr.h` | `libmxfs/scsipr.h` | Remove linux headers |
| `kernel/mxfs_journal.c` (~170 lines) | `libmxfs/journal.c` | Slot claiming and recovery coordination stays identical. |
| `kernel/mxfs_journal.h` | `libmxfs/journal.h` | Remove linux headers |
| `kernel/mxfs_lockcache.c` (lock cache portion) | `libmxfs/inode_cache.c` | Per-inode lock caching logic (fast path/slow path, holder counting, BAST response) ports to inode cache. XFS data fork patching code is discarded (no longer needed — we own the cache). |

### Written from scratch
| File | What it does |
|---------|-------------|
| `libmxfs/xfs_format.c/h` | XFS on-disk format parser: superblock, AG headers, B+ trees, dinode, directory formats. Reference: xfsprogs source (`libxfs/`) and XFS documentation. Key structures: `xfs_sb` (superblock), `xfs_agi`/`xfs_agf` (AG headers), `xfs_dinode` (inode), `xfs_dir2_sf_hdr` (shortform dir), `xfs_da_intnode` (btree node). |
| `libmxfs/block_cache.c/h` | DLM-aware block cache with dirty tracking, LRU eviction, write coalescing, and BAST-triggered flush+drop. |
| `libmxfs/dir_cache.c/h` | Directory entry cache (name→ino mapping). Parses all 4 XFS dir formats. |
| `libmxfs/alloc.c/h` | Inode and block allocation using XFS inobt/bnobt/cntbt B+ trees. AG-level DLM locking. |
| `libmxfs/extent.c/h` | Extent map parsing (inline list and B+ tree) and management for file data. |
| `libmxfs/mount.c/h` | Mount orchestration: open device, read superblock, init caches, init DLM, init peers, start discovery/leases. |
| `pal/pal.h` | Platform abstraction interface. |
| `pal/pal_linux_user.c` | Linux userspace PAL (O_DIRECT, pthreads, POSIX sockets) — first implementation, used for development. |

### Discarded (superseded)
Old stacking FS code (`kernel/`) and daemon (`daemon/`) have been removed.
All functionality now lives in libmxfs (portable core) + frontend/linux/ (VFS glue).

## XFS On-Disk Format Quick Reference

The new session will need to implement XFS format parsing. Key references:
- **Linux XFS source**: `~/src/linux/fs/xfs/libxfs/` — authoritative on-disk format definitions and implementation
  - `xfs_format.h` — every on-disk structure (superblock, AG headers, dinode, etc.)
  - `xfs_da_format.h` — directory and attribute on-disk format structures
  - `xfs_dir2.h` / `xfs_dir2_priv.h` — directory format details and operations
  - `xfs_ialloc.h` — inode allocation structures
  - `xfs_alloc.h` — block allocation structures
  - `xfs_btree.h` — generic B+ tree framework
  - `xfs_bmap_btree.h` — extent map B+ tree (file block mapping)
- **XFS Algorithms & Data Structures doc**: https://xfs.wiki.kernel.org/
- v1's `kernel/mxfs_lockcache.c` already has working XFS superblock and inode parsing (lines 50-260) that can serve as a starting point

### Critical XFS structures to parse

**Superblock** (`xfs_sb`, sector 0 of AG 0): blocksize, AG count, AG size, inode size, root inode number, journal location, UUID, feature flags.

**AG Headers** (first 4 sectors of each AG):
- `xfs_agf` — free space info (bnobt/cntbt roots, free block count)
- `xfs_agi` — inode info (inobt/finobt roots, inode count, free inode count)

**Inode** (`xfs_dinode`, 512 bytes for v5):
- Core (176 bytes): magic, mode, version, format, uid, gid, nlink, size, timestamps, extent count
- Data fork (after core): inline data, extent list, or B+ tree root
- Attr fork (optional): extended attributes

**Directory formats** (in order of size):
1. **Shortform**: entries inline in inode data fork. `xfs_dir2_sf_hdr` + `xfs_dir2_sf_entry[]`
2. **Block**: single 4K block with header + entries + leaf tail. Transition at ~10 entries.
3. **Leaf**: multiple data blocks + one leaf block with hash→block index
4. **Node/Btree**: multiple data blocks + multi-level B+ tree index

**Extent list**: array of `xfs_bmbt_rec` (128-bit packed: startoff, startblock, blockcount, flag)

**B+ tree nodes**: `xfs_btree_block` header + key/pointer pairs (internal) or records (leaf)

## DLM Transport Scalability

MXFS supports two DLM transports with different scalability characteristics:

| Transport | Max Tested | Recommended Max | Notes |
|-----------|-----------|----------------|-------|
| **TCP** (`dlm_transport=tcp`) | 32 nodes | **16 nodes** | Single lock-master-per-resource creates serial bottleneck |
| **CAW** (default) | 6 nodes | **64 nodes** | Disk-based locking, no master node |

### TCP DLM Limits

TCP DLM uses a single lock-master-per-resource design where one node arbitrates all lock requests for each resource. At high node counts, this creates a serial bottleneck:

- **16 nodes**: 100% metadata completion, full data I/O throughput
- **32 nodes**: ~27% metadata completion, only 6/32 nodes complete data I/O before timeout

The filesystem remains **correct** at 32 nodes (zero crashes, zero data corruption), but lock wait times exceed VFS operation timeouts, causing I/O errors. A dmesg warning is emitted when the TCP DLM cluster exceeds 16 nodes.

For clusters larger than 16 nodes, use CAW DLM (the default) with a SCSI device that supports Compare-And-Write (iSCSI with LIO `emulate_caw=1`, or native SCSI storage).

## Test Environment

- **4 Linux VMs**: 192.168.120.201-204, Debian 11, kernel 5.10
- **Shared iSCSI LUN**: 50GB on local dev machine (192.168.120.1, NVMe-backed), `/dev/sdb`
- **Dev machine**: Ubuntu, kernel 6.8
- **Deploy**: `tools/mxfs_deploy.sh`, SSH: `tools/mxfs_ssh.exp`
- **ESXi**: 192.168.1.251, VM IDs: 156(201), 158(202), 159(203), 160(204)

## Compatibility

- **On-disk format**: Standard XFS. `mkfs.xfs`, `xfs_repair`, `xfs_db` all work.
- **Wire protocol**: Same DLM messages, same discovery, same leases as v1. Protocol version stays at 1.
- **Disklock format**: Same `.mxfs/lockstate` layout as v1.
- **Storage**: Any shared block device — iSCSI, FC, NVMe-oF. Linux LIO, TrueNAS, etc.
- **Network**: Same subnet for UDP multicast discovery. TCP for DLM. Standard IP networking.
