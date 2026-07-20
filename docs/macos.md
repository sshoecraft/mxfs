# MXFS macOS Port — Full Kernel Implementation

## Overview

This document covers porting MXFS to macOS as a full kernel extension (KEXT),
targeting Apple Silicon (M4 Mac Mini). The approach uses the same KEXT
architecture proven in the `macos-vcan` project (`~/src/macos-vcan`).

MXFS on Linux has two components:
1. **mxfs.ko** — Kernel module (stacking filesystem over XFS)
2. **mxfsd** — Userspace daemon (DLM, discovery, fencing, leases)

The macOS port preserves this architecture: MXFS stacks over XFS on every
platform. All nodes — Linux, macOS, eventually Windows — mount the same
XFS-formatted shared block device. The on-disk format is XFS everywhere.

This means **XFS on macOS is a prerequisite**. It must be implemented as a
separate project first, then MXFS stacks over it identically to how it
stacks over XFS on Linux.

---

## Prerequisites

### XFS on macOS (Separate Project)

MXFS requires XFS underneath it on every platform. There is no macOS XFS
implementation today (SGI's old one was read-only FUSE, long abandoned).
A full read-write XFS implementation for macOS is required before MXFS
can run.

#### What XFS-on-Mac Needs

- **Read-write XFS filesystem** — not read-only, not FUSE
- **KEXT using macOS VFS KPI** — `vfs_fsadd()`, vnop handlers, `buf_bread()`/`buf_bwrite()`
- **On-disk compatibility** — must read/write the same XFS format as Linux `mkfs.xfs`
- **Journal support** — XFS log replay for crash recovery
- **Allocation groups** — XFS's core space management structure
- **B+tree operations** — XFS uses B+trees for inodes, extents, directories
- **Inode formats** — short-form, extent-list, and B+tree extent formats
- **Directory formats** — short-form, block, leaf, node, and B+tree directories

#### Scope of XFS

The Linux XFS implementation is ~100K+ lines across `fs/xfs/`. However, not
all of it is needed for an initial port:

**Required for basic functionality**:
- Superblock reading/validation (`xfs_sb.h`)
- Allocation group management (`xfs_ag.h`)
- Inode read/write (`xfs_dinode.h`, `xfs_inode.h`)
- Extent mapping / B+tree (`xfs_bmbt.h`, `xfs_btree.h`)
- Directory operations (`xfs_dir2.h`)
- Free space management (`xfs_alloc.h`)
- Journal / log (`xfs_log.h`, `xfs_log_recover.h`)
- Buffer I/O layer (`xfs_buf.h`)

**Can be deferred**:
- Quotas (`xfs_quota.h`)
- Real-time subvolume (`xfs_rtalloc.h`)
- Online repair / scrub
- Reflink / dedupe
- DAX (direct access)

#### XFS Portability History

XFS was originally written for IRIX (SGI) and was designed to be portable.
The Linux port introduced a platform abstraction layer. Key portability
considerations:

- **`libxfs`**: The Linux xfsprogs package contains a userspace `libxfs`
  that shares code with the kernel. This library compiles on multiple
  platforms (Linux, FreeBSD partially) and provides the core XFS data
  structure manipulation code. It can serve as a starting point.
- **FreeBSD**: Had read-only XFS support at one point (removed in FreeBSD 12).
  Some of that porting work may be instructive.
- **xfsprogs**: The userspace tools (`mkfs.xfs`, `xfs_repair`, `xfs_db`)
  compile on macOS with modifications. Getting these working first is a
  good validation step.

#### XFS-on-Mac Implementation Path

1. **Get xfsprogs compiling on macOS** — `mkfs.xfs`, `xfs_db`, `xfs_repair`.
   This validates that the on-disk format parsing code works on the platform
   and gives you tools to create and inspect test filesystems.

2. **Build a read-only XFS KEXT** — Mount XFS, read superblock, traverse
   allocation groups, resolve inodes, read files and directories. No write
   path yet. Uses `buf_bread()` for block I/O.

3. **Add write support** — Inode modification, extent allocation, directory
   updates, free space management. Uses `buf_bwrite()`.

4. **Add journal support** — XFS log write and replay. Required for crash
   recovery and for MXFS multi-node journal replay.

5. **Test with MXFS** — Stack MXFS over the XFS KEXT. At this point the
   macOS MXFS stacking code can be developed.

#### Apple Developer Program Requirement

Both the XFS KEXT and the MXFS KEXT require either:
- **Development**: SIP disabled (same as macos-vcan). No signing needed.
- **Production/Distribution**: Apple Developer Program ($99/year) with a
  KEXT signing certificate. Apple has been restricting new KEXT signing
  approvals — they prefer DriverKit/FSKit.

For development and personal/lab use, SIP disabled works. Apple Developer
Program is needed for distribution to machines with SIP enabled.

---

## Project Dependency Chain

```
1. XFS on macOS (separate project — xfs-macos)
   ├── xfsprogs port (userspace tools)
   ├── Read-only XFS KEXT
   ├── Read-write XFS KEXT
   └── Journal support
         │
         v
2. MXFS on macOS (this project — mxfs, same repo)
   ├── Daemon porting (3 files)
   ├── MXFS KEXT (stacks over XFS KEXT)
   └── Integration testing
```

Both KEXTs load together. On mount:
1. MXFS KEXT internally mounts XFS on the block device (via XFS KEXT)
2. MXFS wraps XFS vnodes with DLM lock acquire/release
3. mxfsd daemon handles clustering, same as Linux

---

## Repository Structure

MXFS remains a single repo with platform-specific kernel directories.
The daemon code uses `#ifdef __APPLE__` / `#ifdef __linux__` for the
3 files that differ. Everything else compiles on both platforms unchanged.

```
mxfs/                              # single repo, both platforms
├── include/mxfs/                  # shared headers (both platforms)
│   ├── mxfs_common.h
│   ├── mxfs_dlm.h
│   └── mxfs_netlink.h            # Linux netlink + macOS ctl msg defs
├── kernel/                        # Linux kernel module (existing)
│   ├── mxfs_main.c
│   ├── mxfs_super.c
│   ├── mxfs_inode.c
│   ├── mxfs_file.c
│   ├── mxfs_dir.c
│   ├── mxfs_netlink.c
│   ├── mxfs_cache.c
│   ├── mxfs_lockcache.c
│   ├── mxfs_internal.h
│   └── Makefile
├── darwin/                        # macOS kernel module (new)
│   ├── mxfs_main.c               # vfs_fsadd/vfs_fsremove, KMOD_EXPLICIT_DECL
│   ├── mxfs_vfsops.c             # mount/unmount/root/statfs/sync
│   ├── mxfs_vnops.c              # VNOP_* handlers with DLM lock wrapping
│   ├── mxfs_ctl.c                # kern_control socket (replaces genetlink)
│   ├── mxfs_cache.c              # UBC invalidation
│   ├── mxfs_lockcache.c          # Per-vnode lock cache
│   ├── mxfs_internal.h           # vnode info, mount info, accessors
│   ├── Info.plist                 # KEXT bundle metadata
│   └── Makefile                   # Same pattern as macos-vcan
├── daemon/                        # userspace daemon (both platforms)
│   ├── mxfsd_main.c              # cross-platform
│   ├── mxfsd_peer.c              # cross-platform
│   ├── mxfsd_dlm.c               # cross-platform
│   ├── mxfsd_discovery.c         # cross-platform
│   ├── mxfsd_lease.c             # cross-platform
│   ├── mxfsd_journal.c           # cross-platform
│   ├── mxfsd_volume.c            # cross-platform
│   ├── mxfsd_config.c            # cross-platform
│   ├── mxfsd_log.c               # cross-platform
│   ├── mxfsd_netlink.c           # #ifdef __linux__ (genetlink)
│   ├── mxfsd_ctl.c               # #ifdef __APPLE__ (kern_control)
│   ├── mxfsd_scsi_pr.c           # #ifdef per platform (SG_IO vs IOKit)
│   ├── mxfsd_disklock.c          # #ifdef for O_DIRECT vs F_NOCACHE
│   └── Makefile                   # detects platform, builds accordingly
├── tools/
│   ├── mxfs_lock.c               # cross-platform
│   └── mount_mxfs.c              # macOS mount helper (new)
├── config/
│   ├── volumes.conf.example
│   └── com.mxfs.daemon.plist     # macOS launchd config (new)
└── docs/
    ├── architecture.md
    ├── dlm-protocol.md
    └── macos.md                   # this document
```

---

## Daemon Portability Assessment

### Works Unchanged on macOS (9 of 12 files)

| File | What It Does | Why It's Portable |
|------|-------------|-------------------|
| `mxfsd_peer.c` | TCP peer connections | Standard BSD sockets |
| `mxfsd_dlm.c` | DLM protocol engine | Pure data structures + pthreads |
| `mxfsd_discovery.c` | UDP multicast/broadcast discovery | Standard BSD sockets |
| `mxfsd_lease.c` | Lease-based node liveness | `clock_gettime(CLOCK_MONOTONIC)` works since macOS 10.12 |
| `mxfsd_journal.c` | Journal slot management | Pure state machine, pthreads |
| `mxfsd_log.c` | Logging | `syslog()` API exists on macOS (routes to unified log) |
| `mxfsd_volume.c` | Volume state tracking | Standard file I/O |
| `mxfsd_config.c` | Config defaults | Pure C |
| `mxfsd_main.c` | Main loop, signals | `sigaction()`, pthreads, Unix sockets all compatible |

All threading (pthreads mutexes, condvars, rwlocks), signal handling
(`sigaction`, `SIGTERM`, `SIGPIPE`), Unix domain sockets (`AF_UNIX`),
TCP/IPv4 networking, `poll()`, `fcntl(O_NONBLOCK)`, `nanosleep()`, and
`/dev/urandom` work identically on macOS.

### Requires Porting (3 files)

#### mxfsd_netlink.c → mxfsd_ctl.c (kernel control socket)

**Linux**: `AF_NETLINK` / `NETLINK_GENERIC` raw genetlink socket. Resolves
the "mxfs" genetlink family via `CTRL_CMD_GETFAMILY`. Sends/receives
structured NLA messages.

**macOS**: No generic netlink. Replace with `PF_SYSTEM` / `SYSPROTO_CONTROL`
kernel control socket:

```c
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
struct ctl_info info;
strlcpy(info.ctl_name, "com.mxfs.ctl", sizeof(info.ctl_name));
ioctl(fd, CTLIOCGINFO, &info);

struct sockaddr_ctl addr = {
    .sc_len = sizeof(addr),
    .sc_family = AF_SYSTEM,
    .ss_sysaddr = AF_SYS_CONTROL,
    .sc_id = info.ctl_id,
    .sc_unit = 0,
};
connect(fd, (struct sockaddr *)&addr, sizeof(addr));

// Now send/recv binary messages — same wire format as netlink payload
```

The 14 MXFS netlink commands (LOCK_REQ, LOCK_GRANT, LOCK_RELEASE, LOCK_DENY,
CACHE_INVAL, NODE_STATUS, VOLUME_MOUNT, VOLUME_UMOUNT, STATUS_REQ,
STATUS_RESP, RECOVERY_START, RECOVERY_DONE, DAEMON_READY, LOCK_BAST)
transfer unchanged — only the transport layer changes. Strip the NLA/netlink
headers and use a simpler length-prefixed or fixed-size message framing.

**Effort**: Medium. Same message semantics, different socket family.

#### mxfsd_scsi_pr.c → IOKit SCSI Architecture Model

**Linux**: `SG_IO` ioctl on `/dev/sdX` for raw SCSI CDB passthrough.
Sends PERSISTENT RESERVE IN (0x5E) and PERSISTENT RESERVE OUT (0x5F)
commands. Uses `struct sg_io_hdr` for command/response/sense buffers.

**macOS**: No `SG_IO`. Use IOKit SCSI Architecture Model from userspace:

```c
#include <IOKit/scsi/SCSITaskLib.h>

// 1. Find the SCSI device via IOKit matching
CFDictionaryRef match = IOServiceMatching(kIOSCSIPeripheralDeviceNubKey);
io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, match);

// 2. Create plugin interface
IOCFPlugInInterface **plugin;
IOCreatePlugInInterfaceForService(service, kIOSCSITaskDeviceUserClientTypeID,
                                   kIOCFPlugInInterfaceID, &plugin, &score);

// 3. Get SCSITaskDeviceInterface
SCSITaskDeviceInterface **dev;
(*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOSCSITaskDeviceInterfaceID),
                          (LPVOID *)&dev);

// 4. Obtain exclusive access
(*dev)->ObtainExclusiveAccess(dev);

// 5. Create and execute SCSI task
SCSITaskInterface **task = (*dev)->CreateSCSITask(dev);
(*task)->SetCommandDescriptorBlock(task, cdb, cdb_len);
(*task)->SetScatterGatherEntries(task, &sgElement, 1, transfer_len,
                                  kSCSIDataTransfer_FromTargetToInitiator);
(*task)->SetTimeoutDuration(task, 10000);  // 10 seconds
(*task)->ExecuteTaskSync(task, &senseData, &taskStatus, &transferCount);
```

Same PR IN/PR OUT CDBs, same sense data parsing. Different transport.
Apple's IOKit SCSI interface is actually cleaner than Linux's `SG_IO` ioctl.

**Effort**: Medium. Same SCSI commands, different submission API.

#### mxfsd_disklock.c — O_DIRECT and fallocate

**Linux**: `O_DIRECT | O_SYNC` for sector-aligned atomic writes.
`fallocate()` for pre-allocation. `posix_memalign()` for aligned buffers.

**macOS substitutions**:

| Linux | macOS | Notes |
|-------|-------|-------|
| `O_DIRECT` | `fcntl(fd, F_NOCACHE, 1)` | Disables buffer cache for the fd |
| `O_SYNC` | `O_SYNC` or `fcntl(fd, F_FULLFSYNC)` | `F_FULLFSYNC` flushes drive cache too |
| `fallocate(fd, 0, 0, size)` | `fcntl(fd, F_PREALLOCATE, &store)` | Uses `fstore_t` struct |
| `posix_memalign()` | `posix_memalign()` | Works identically |
| `pread()` / `pwrite()` | `pread()` / `pwrite()` | Works identically |

Pre-allocation on macOS:
```c
fstore_t store = {
    .fst_flags = F_ALLOCATEALL,
    .fst_posmode = F_PEOFPOSMODE,
    .fst_offset = 0,
    .fst_length = desired_size,
};
fcntl(fd, F_PREALLOCATE, &store);
ftruncate(fd, desired_size);
```

**Effort**: Trivial. A few `#ifdef __APPLE__` blocks.

---

## Kernel Module — macOS KEXT (darwin/)

The Linux kernel module uses 180+ Linux-specific APIs. The macOS KEXT uses
entirely different frameworks: VFS KPI, kernel control sockets, UBC.

The macOS MXFS KEXT stacks over the XFS KEXT, same as the Linux module
stacks over the in-kernel XFS. The stacking pattern on macOS works by
holding references to lower XFS vnodes and delegating operations to them.

### KPI Dependencies (Info.plist)

Same pattern as macos-vcan, but with BSD KPI emphasis:

```xml
<key>OSBundleLibraries</key>
<dict>
    <key>com.apple.kpi.bsd</key>
    <string>8.0</string>
    <key>com.apple.kpi.libkern</key>
    <string>8.0</string>
    <key>com.apple.kpi.mach</key>
    <string>8.0</string>
    <key>com.apple.kpi.iokit</key>
    <string>8.0</string>
</dict>
```

The filesystem primarily uses BSD KPI (`sys/mount.h`, `sys/vnode.h`,
`sys/kern_control.h`, `sys/ubc.h`). IOKit is used only for KEXT lifecycle.

### Build System

Same pattern as macos-vcan Makefile:

```makefile
CC = xcrun clang
CFLAGS = -arch arm64 -mkernel -fno-exceptions -fno-stack-protector \
         -D__KERNEL__ -DKERNEL_PRIVATE -DKERNEL \
         -I$(SDKROOT)/System/Library/Frameworks/Kernel.framework/Headers
LDFLAGS = -arch arm64 -nostdlib -r -lkmod -lcc_kext
```

No C++ needed (unlike macos-vcan which uses IOService). The filesystem
KEXT is pure C using BSD VFS KPI.

### Filesystem Registration (mxfs_main.c)

```c
#include <sys/mount.h>
#include <sys/vnode.h>

static vfstable_t mxfs_vfshandle;

// VFS operations table
static struct vfsops mxfs_vfsops = {
    .vfs_mount    = mxfs_vfs_mount,
    .vfs_unmount  = mxfs_vfs_unmount,
    .vfs_root     = mxfs_vfs_root,
    .vfs_getattr  = mxfs_vfs_getattr,
    .vfs_sync     = mxfs_vfs_sync,
    .vfs_init     = mxfs_vfs_init,
};

// Filesystem entry for vfs_fsadd()
static struct vfs_fsentry mxfs_fsentry = {
    .vfe_vfsops   = &mxfs_vfsops,
    .vfe_vopcnt   = 1,
    .vfe_opvdescs = mxfs_vnodeop_descs,
    .vfe_fstypenum = 0,                   // assigned by kernel
    .vfe_fsname   = "mxfs",
    .vfe_flags    = VFS_TBLTHREADSAFE | VFS_TBLFSNODELOCK
                  | VFS_TBL64BITREADY | VFS_TBLNOTYPENUM,
};

kern_return_t mxfs_start(kmod_info_t *ki, void *data)
{
    int err = vfs_fsadd(&mxfs_fsentry, &mxfs_vfshandle);
    if (err) return KERN_FAILURE;
    mxfs_ctl_init();
    return KERN_SUCCESS;
}

kern_return_t mxfs_stop(kmod_info_t *ki, void *data)
{
    mxfs_ctl_exit();
    vfs_fsremove(mxfs_vfshandle);
    return KERN_SUCCESS;
}
```

### VFS Operations — Stacking Over XFS (mxfs_vfsops.c)

#### Mount

On Linux, `vfs_kern_mount("xfs")` mounts XFS internally. macOS doesn't
have `vfs_kern_mount()`. The stacking approach on macOS:

**Option A — Require XFS pre-mounted**: User mounts XFS first, then MXFS
mounts over the XFS mountpoint. MXFS finds the lower XFS mount via
`vnode_mount()` on the covered vnode.

```bash
# User workflow (two-step):
mount -t xfs /dev/disk2 /mnt/xfs_lower
mount -t mxfs /mnt/xfs_lower /mnt/shared
```

**Option B — MXFS triggers XFS mount internally**: MXFS calls `kernel_mount()`
(private KPI) to mount XFS on the block device, then stacks over it.
More like the Linux model but relies on private API.

**Option C — Mount helper handles it**: The `mount_mxfs` userspace helper
mounts XFS first, then tells the kernel to mount MXFS over it. Cleanest
separation — kernel KEXT doesn't need private mount APIs.

```c
// mount_mxfs helper (userspace):
// 1. mount("xfs", lower_mountpoint, MNT_RDONLY, &xfs_args);
// 2. mount("mxfs", user_mountpoint, 0, &mxfs_args);
//    mxfs_args.lower_path = lower_mountpoint;
```

Option C is recommended — it keeps the KEXT simpler and avoids private KPI.

```c
static int mxfs_vfs_mount(struct mount *mp, vnode_t devvp,
                           user_addr_t data, vfs_context_t ctx)
{
    struct mxfs_mount_args args;
    copyin(data, &args, sizeof(args));

    struct mxfs_mount_info *mmi = OSMalloc(sizeof(*mmi), mxfs_malloc_tag);

    // Get the lower XFS mount (already mounted by mount_mxfs helper)
    vnode_t lower_root;
    int err = vnode_lookup(args.lower_path, 0, &lower_root, ctx);
    if (err) goto fail;

    mmi->lower_mp = vnode_mount(lower_root);
    mmi->lower_root = lower_root;

    // Read XFS superblock UUID for volume_id
    // (via vnode_getattr on lower root, or read device directly)
    mxfs_read_volume_uuid(mmi);

    // Create MXFS root vnode wrapping XFS root vnode
    mxfs_vnode_create(mp, lower_root, VDIR, &mmi->root_vp);

    vfs_setfsprivate(mp, mmi);

    // Start daemon via kernel control socket notification
    mxfs_ctl_notify_mount(mmi);

    // Wait for daemon DAEMON_READY
    struct timespec ts = { .tv_sec = 30 };
    msleep(&mmi->daemon_ready, mmi->mtx, PRIBIO, "mxfs_mount", &ts);

    return 0;
}
```

#### Unmount

```c
static int mxfs_vfs_unmount(struct mount *mp, int mntflags,
                             vfs_context_t ctx)
{
    struct mxfs_mount_info *mmi = vfs_fsprivate(mp);

    int flags = (mntflags & MNT_FORCE) ? FORCECLOSE : 0;
    vflush(mp, mmi->root_vp, flags);

    // Signal daemon to shut down
    mxfs_ctl_notify_unmount(mmi);

    // Release lower XFS root vnode
    vnode_put(mmi->lower_root);

    // mount_mxfs helper unmounts the lower XFS after MXFS unmounts

    OSFree(mmi, sizeof(*mmi), mxfs_malloc_tag);
    vfs_setfsprivate(mp, NULL);
    return 0;
}
```

### Vnode Operations — Stacking Pattern (mxfs_vnops.c)

Each MXFS vnode holds a pointer to the lower XFS vnode. Operations
acquire a DLM lock, call the lower XFS vnop, release the lock, and
copy attributes back up. Same pattern as Linux, different API.

#### Vnop Descriptor Table

```c
#include <sys/vnode_if.h>

static struct vnodeopv_entry_desc mxfs_vnodeop_entries[] = {
    { &vnop_default_desc,  (VOPFUNC)vn_default_error },
    { &vnop_lookup_desc,   (VOPFUNC)mxfs_vnop_lookup },
    { &vnop_create_desc,   (VOPFUNC)mxfs_vnop_create },
    { &vnop_open_desc,     (VOPFUNC)mxfs_vnop_open },
    { &vnop_close_desc,    (VOPFUNC)mxfs_vnop_close },
    { &vnop_read_desc,     (VOPFUNC)mxfs_vnop_read },
    { &vnop_write_desc,    (VOPFUNC)mxfs_vnop_write },
    { &vnop_getattr_desc,  (VOPFUNC)mxfs_vnop_getattr },
    { &vnop_setattr_desc,  (VOPFUNC)mxfs_vnop_setattr },
    { &vnop_remove_desc,   (VOPFUNC)mxfs_vnop_remove },
    { &vnop_link_desc,     (VOPFUNC)mxfs_vnop_link },
    { &vnop_rename_desc,   (VOPFUNC)mxfs_vnop_rename },
    { &vnop_mkdir_desc,    (VOPFUNC)mxfs_vnop_mkdir },
    { &vnop_rmdir_desc,    (VOPFUNC)mxfs_vnop_rmdir },
    { &vnop_symlink_desc,  (VOPFUNC)mxfs_vnop_symlink },
    { &vnop_readdir_desc,  (VOPFUNC)mxfs_vnop_readdir },
    { &vnop_fsync_desc,    (VOPFUNC)mxfs_vnop_fsync },
    { &vnop_mmap_desc,     (VOPFUNC)mxfs_vnop_mmap },
    { &vnop_strategy_desc, (VOPFUNC)mxfs_vnop_strategy },
    { &vnop_reclaim_desc,  (VOPFUNC)mxfs_vnop_reclaim },
    { &vnop_inactive_desc, (VOPFUNC)mxfs_vnop_inactive },
    { NULL, NULL },
};

static struct vnodeopv_desc mxfs_vnodeop_desc = {
    &mxfs_vnodeop_p,
    mxfs_vnodeop_entries,
};

static struct vnodeopv_desc *mxfs_vnodeop_descs[] = {
    &mxfs_vnodeop_desc,
};
```

#### Stacking Example — Write

```c
static int mxfs_vnop_write(struct vnop_write_args *ap)
{
    vnode_t vp = ap->a_vp;
    struct mxfs_vnode_info *mvi = vnode_fsnode(vp);
    vnode_t lower_vp = mvi->lower_vp;

    // 1. Acquire DLM lock (EX for write)
    int err = mxfs_lock_vnode(mvi, MXFS_LOCK_EX);
    if (err) return err;

    // 2. Delegate to lower XFS vnode
    err = VNOP_WRITE(lower_vp, ap->a_uio, ap->a_ioflag, ap->a_context);

    // 3. Copy attributes back up from lower vnode
    mxfs_copy_attrs(vp, lower_vp);

    // 4. Release DLM lock (decrement holders only — cached)
    mxfs_unlock_vnode(mvi);

    return err;
}
```

#### Stacking Example — Lookup

```c
static int mxfs_vnop_lookup(struct vnop_lookup_args *ap)
{
    vnode_t dvp = ap->a_dvp;
    vnode_t *vpp = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    struct mxfs_vnode_info *dmvi = vnode_fsnode(dvp);
    vnode_t lower_dvp = dmvi->lower_vp;

    // 1. Acquire DLM lock (PR for lookup)
    int err = mxfs_lock_vnode(dmvi, MXFS_LOCK_PR);
    if (err) return err;

    // 2. Lookup in lower XFS directory
    vnode_t lower_vp = NULLVP;
    err = VNOP_LOOKUP(lower_dvp, &lower_vp, cnp, ap->a_context);

    if (!err && lower_vp != NULLVP) {
        // 3. Create or find MXFS vnode wrapping the lower XFS vnode
        err = mxfs_vnode_get_or_create(vnode_mount(dvp), lower_vp, vpp);
    }

    // 4. Release DLM lock
    mxfs_unlock_vnode(dmvi);

    return err;
}
```

### DLM Lock Policy (same as Linux)

| Operation | Lock Target | Mode | Rationale |
|-----------|-------------|------|-----------|
| create | parent dir | EX | Modifies directory |
| lookup | parent dir | PR | Read-only dir scan |
| link | target dir | EX | Modifies directory |
| remove | parent dir | EX | Modifies directory |
| symlink | parent dir | EX | Modifies directory |
| mkdir | parent dir | EX | Modifies directory |
| rmdir | parent dir | EX | Modifies directory |
| rename | both dirs | EX | Lock in ino order (deadlock avoidance) |
| getattr | target vnode | PR | Read-only |
| setattr | target vnode | EX | Modifies metadata |
| open | file vnode | CR | Coherent vnode needed |
| close | — | none | Cleanup only |
| read | file vnode | PR | Shared read |
| write | file vnode | EX | Exclusive write |
| fsync | file vnode | EX | Flush + barrier |
| readdir | dir vnode | PR | Read-only dir scan |

### Kernel ↔ Daemon Communication (mxfs_ctl.c)

#### Kernel Side — kern_control.h

```c
#include <sys/kern_control.h>

static kern_ctl_ref mxfs_ctl_ref;

static struct kern_ctl_reg mxfs_ctl_reg = {
    .ctl_name    = "com.mxfs.ctl",
    .ctl_id      = 0,                  // dynamically assigned
    .ctl_unit    = 0,
    .ctl_flags   = CTL_FLAG_PRIVILEGED,
    .ctl_sendsize = 65536,
    .ctl_recvsize = 65536,
    .ctl_connect    = mxfs_ctl_connect,
    .ctl_disconnect = mxfs_ctl_disconnect,
    .ctl_send       = mxfs_ctl_send,     // daemon → kernel
    .ctl_getopt     = NULL,
    .ctl_setopt     = NULL,
};

int mxfs_ctl_init(void)
{
    return ctl_register(&mxfs_ctl_reg, &mxfs_ctl_ref);
}

void mxfs_ctl_exit(void)
{
    ctl_deregister(mxfs_ctl_ref);
}

// Daemon connects: store its unit for sending messages back
static int mxfs_ctl_connect(kern_ctl_ref ref, struct sockaddr_ctl *sac,
                             void **unitinfo)
{
    struct mxfs_ctl_client *client = OSMalloc(sizeof(*client), mxfs_tag);
    client->unit = sac->sc_unit;
    *unitinfo = client;
    return 0;
}

// Daemon sends a message to kernel (lock grant, cache inval, etc.)
static int mxfs_ctl_send(kern_ctl_ref ref, unsigned int unit,
                          void *unitinfo, mbuf_t m, int flags)
{
    struct mxfs_ctl_msg *msg = mbuf_data(m);
    switch (msg->cmd) {
    case MXFS_CMD_LOCK_GRANT:    mxfs_handle_lock_grant(msg);    break;
    case MXFS_CMD_LOCK_DENY:     mxfs_handle_lock_deny(msg);     break;
    case MXFS_CMD_CACHE_INVAL:   mxfs_handle_cache_inval(msg);   break;
    case MXFS_CMD_DAEMON_READY:  mxfs_handle_daemon_ready(msg);  break;
    case MXFS_CMD_RECOVERY_START: mxfs_handle_recovery_start(msg); break;
    case MXFS_CMD_RECOVERY_DONE: mxfs_handle_recovery_done(msg); break;
    case MXFS_CMD_LOCK_BAST:     mxfs_handle_lock_bast(msg);     break;
    }
    return 0;
}

// Kernel sends a message to daemon (lock request, lock release, etc.)
static int mxfs_ctl_send_to_daemon(struct mxfs_mount_info *mmi,
                                    struct mxfs_ctl_msg *msg, size_t len)
{
    return ctl_enqueuedata(mxfs_ctl_ref, mmi->daemon_unit, msg, len, 0);
}
```

#### Daemon Side — PF_SYSTEM Socket

```c
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

int mxfs_ctl_connect(void)
{
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    struct ctl_info info = {};
    strlcpy(info.ctl_name, "com.mxfs.ctl", sizeof(info.ctl_name));
    ioctl(fd, CTLIOCGINFO, &info);

    struct sockaddr_ctl addr = {
        .sc_len     = sizeof(addr),
        .sc_family  = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_id      = info.ctl_id,
        .sc_unit    = 0,
    };
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    return fd;
}
```

### Message Format

Replace netlink NLA attributes with a simple fixed-size message. All 14
command types fit in one struct:

```c
struct mxfs_ctl_msg {
    uint8_t  cmd;           // MXFS_CMD_LOCK_REQ, MXFS_CMD_LOCK_GRANT, etc.
    uint8_t  lock_mode;     // DLM lock mode (NL/CR/CW/PR/PW/EX)
    uint8_t  lock_flags;    // NOQUEUE, TRYLOCK, etc.
    uint8_t  status;        // grant/deny status
    uint32_t volume_id;     // FNV-1a hash of volume UUID
    uint64_t ino;           // inode number
    uint64_t offset;        // byte offset (for range ops)
    uint64_t length;        // byte length (for range ops)
    uint32_t node_id;       // source node ID
    uint32_t pid;           // daemon PID
    uint8_t  resource[32];  // DLM resource ID
    uint8_t  uuid[16];      // volume or node UUID
};
```

This format could also be adopted on Linux (replacing the netlink NLA
encoding) for a simpler, unified message format across platforms.

### Page Cache / UBC (mxfs_cache.c)

macOS Unified Buffer Cache replaces Linux page cache:

| Linux API | macOS API | Header |
|-----------|-----------|--------|
| `invalidate_inode_pages2(mapping)` | `ubc_msync(vp, 0, filesize, NULL, UBC_INVALIDATE)` | `<sys/ubc.h>` |
| `invalidate_inode_pages2_range(mapping, start, end)` | `ubc_msync(vp, off, off+len, NULL, UBC_INVALIDATE)` | `<sys/ubc.h>` |
| `truncate_inode_pages_final(&inode->i_data)` | `ubc_setsize(vp, 0)` | `<sys/ubc.h>` |
| `ilookup(sb, ino)` | Internal hash table in mount info | — |

Invalidation handler called when daemon sends `MXFS_CMD_CACHE_INVAL`:

```c
static void mxfs_handle_cache_inval(struct mxfs_ctl_msg *msg)
{
    struct mxfs_mount_info *mmi = mxfs_find_mount(msg->volume_id);
    if (!mmi) return;

    vnode_t vp = mxfs_find_vnode(mmi, msg->ino);
    if (!vp) return;    // not cached, nothing to invalidate

    if (msg->length == 0) {
        ubc_msync(vp, 0, mxfs_vnode_size(vp), NULL, UBC_INVALIDATE);
    } else {
        ubc_msync(vp, msg->offset, msg->offset + msg->length,
                  NULL, UBC_INVALIDATE);
    }

    vnode_put(vp);
}
```

### Per-Vnode Lock Cache (mxfs_lockcache.c)

Nearly direct port. Replace Linux inode with macOS vnode:

| Linux | macOS |
|-------|-------|
| `struct mxfs_inode_info` | `struct mxfs_vnode_info` (stored via `vnode_fsnode()`) |
| `spinlock_t lock_spin` | `lck_spin_t lock_spin` (from `<kern/locks.h>`) |
| `atomic_t lock_holders` | `volatile int32_t lock_holders` with `OSAtomicIncrement32()` |
| `struct work_struct bast_work` | `thread_call_t bast_call` (from `<kern/thread_call.h>`) |
| `schedule_work()` | `thread_call_enter(bast_call)` |
| `cancel_work_sync()` | `thread_call_cancel(bast_call)` |
| `ilookup(sb, ino)` | Internal hash table in mount info |

### Vnode Lifecycle

| Linux | macOS | When |
|-------|-------|------|
| `iget_locked()` | `vnode_create(VNCREATE_FLAVOR, ...)` | New vnode needed |
| `unlock_new_inode()` | (vnode is ready after create) | — |
| `igrab()` | `vnode_get(vp)` | Take reference |
| `iput()` | `vnode_put(vp)` | Release reference |
| `ilookup()` | Internal hash + `vnode_get()` | Find by ino |
| `.evict_inode` | `VNOP_RECLAIM` | Vnode being freed |
| `clear_inode()` | Free fsnode data in reclaim | — |

### Memory Management

| Linux | macOS | Header |
|-------|-------|--------|
| `kmem_cache_create()` | `OSMalloc_Tagalloc()` + zones | `<libkern/OSMalloc.h>` |
| `kmem_cache_alloc(GFP_KERNEL)` | `OSMalloc(size, tag)` | `<libkern/OSMalloc.h>` |
| `kmem_cache_free()` | `OSFree(ptr, size, tag)` | `<libkern/OSMalloc.h>` |
| `kmalloc(size, GFP_KERNEL)` | `OSMalloc(size, tag)` | `<libkern/OSMalloc.h>` |
| `kfree(ptr)` | `OSFree(ptr, size, tag)` | `<libkern/OSMalloc.h>` |

Note: `OSFree()` requires knowing the allocation size. Track sizes in
wrapper structs or use fixed-size allocations.

### Synchronization Primitives

| Linux | macOS | Header |
|-------|-------|--------|
| `spinlock_t` | `lck_spin_t` | `<kern/locks.h>` |
| `spin_lock()` / `spin_unlock()` | `lck_spin_lock()` / `lck_spin_unlock()` | `<kern/locks.h>` |
| `rwlock_t` | `lck_rw_t` | `<kern/locks.h>` |
| `read_lock()` / `read_unlock()` | `lck_rw_lock_shared()` / `lck_rw_unlock_shared()` | `<kern/locks.h>` |
| `write_lock()` / `write_unlock()` | `lck_rw_lock_exclusive()` / `lck_rw_unlock_exclusive()` | `<kern/locks.h>` |
| `struct completion` | `msleep()` / `wakeup()` | `<sys/proc.h>` |
| `wait_for_completion_timeout()` | `msleep(chan, mtx, pri, "mxfs", &ts)` | `<sys/proc.h>` |
| `complete()` | `wakeup(chan)` or `wakeup_one(chan)` | `<sys/proc.h>` |
| `atomic_t` | `volatile int32_t` + `OSAtomic*()` | `<libkern/OSAtomic.h>` |
| `struct work_struct` | `thread_call_t` | `<kern/thread_call.h>` |

Lock groups must be allocated:
```c
lck_grp_t *mxfs_lck_grp;
lck_grp_attr_t *mxfs_lck_grp_attr;

// In module init:
mxfs_lck_grp_attr = lck_grp_attr_alloc_init();
mxfs_lck_grp = lck_grp_alloc_init("mxfs", mxfs_lck_grp_attr);

// Allocate a spinlock:
lck_spin_t *lock = lck_spin_alloc_init(mxfs_lck_grp, LCK_ATTR_NULL);
```

### SCSI-3 PR on macOS

Early SCSI PR registration (Linux does this in kernel before XFS mount)
is handled on macOS entirely in the daemon via IOKit SCSI Architecture
Model (see daemon section). This keeps all SCSI PR logic in userspace
and simplifies the KEXT.

---

## Daemon Startup on macOS

### Linux Model

Kernel module spawns daemon via `call_usermodehelper()`:
```
/usr/sbin/mxfsd --device /dev/sdb --mountpoint /mnt/shared --uuid <hex>
```

### macOS Model

The `mount_mxfs` helper handles both XFS and MXFS mount plus daemon start:

```bash
# User runs:
mount -t mxfs /dev/disk2 /Volumes/shared

# macOS calls /sbin/mount_mxfs which:
# 1. Mounts XFS on block device at a lower mountpoint
# 2. Starts mxfsd daemon with --device, --mountpoint, --uuid
# 3. Calls mount(2) for MXFS over the XFS mountpoint
# 4. Daemon connects to kernel control socket, sends DAEMON_READY
# 5. Kernel completes mount
```

Single command from the user's perspective, same as Linux.

Optional launchd plist for daemon management:

**/Library/LaunchDaemons/com.mxfs.daemon.plist**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mxfs.daemon</string>
    <key>Program</key>
    <string>/usr/local/sbin/mxfsd</string>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
```

---

## SIP and Code Signing

### Development

Same as macos-vcan: disable SIP for unsigned KEXT loading.
```
csrutil disable    # from Recovery Mode
sudo kextload xfs.kext
sudo kextload mxfs.kext
```

Both the XFS KEXT and MXFS KEXT load with SIP disabled. No signing needed
for development and personal/lab use.

### Production

Requires Apple Developer Program membership ($99/year) and KEXT signing
certificates. Both KEXTs need signing. Apple has been restricting new
KEXT signing approvals — they prefer DriverKit/FSKit.

### Future — FSKit Migration

FSKit (macOS 15 Sequoia) is Apple's modern filesystem extension framework.
When FSKit matures, both XFS and MXFS could migrate from KEXT to FSKit
without changing the daemon or the DLM protocol.

---

## Implementation Order

### Phase 1 — XFS on macOS (separate project: xfs-macos)

1. **Port xfsprogs to macOS** — Get `mkfs.xfs`, `xfs_db`, `xfs_repair`
   compiling. Validates on-disk format parsing. Gives tools for creating
   and inspecting test filesystems.

2. **Read-only XFS KEXT** — Mount XFS volumes, read superblock, traverse
   AGs, resolve inodes, read files and directories via macOS VFS KPI.

3. **Write support** — Inode modification, extent allocation, directory
   updates, free space management.

4. **Journal support** — XFS log write and replay. Required for crash
   recovery and for MXFS multi-node journal replay.

### Phase 2 — MXFS on macOS (this project, darwin/ directory)

5. **Daemon porting** — Get mxfsd compiling and running on macOS.
   Replace netlink with control socket, SCSI PR with IOKit, O_DIRECT
   with F_NOCACHE. Test DLM, discovery, and peer connectivity between
   Mac and Linux daemons.

6. **Kernel control socket** — Build the simplest possible KEXT that
   registers `com.mxfs.ctl` and can exchange messages with the daemon.
   Verify bidirectional communication works.

7. **MXFS KEXT stacking** — Register "mxfs" via `vfs_fsadd()`, implement
   mount/unmount stacking over XFS KEXT. Verify `mount -t mxfs` works.

8. **Vnode operations** — Implement vnops one at a time: lookup, getattr,
   readdir first (read-only). Then create, write, remove, rename
   (read-write). Each vnop wraps with DLM lock acquire/release and
   delegates to the lower XFS vnode.

9. **Lock caching** — Port mxfs_lockcache using vnode-attached data.

10. **Cache coherency** — Wire UBC invalidation to DLM BAST callbacks.
    Test multi-node cache coherency.

11. **Fencing** — Wire IOKit SCSI PR. Test node failure and recovery.

12. **Integration testing** — Mixed Linux + macOS cluster sharing the
    same XFS LUN. Verify cross-platform DLM, lock contention, cache
    invalidation, journal recovery.

---

## Linux API → macOS API Quick Reference

| Linux | macOS | Header |
|-------|-------|--------|
| `register_filesystem()` | `vfs_fsadd()` | `<sys/mount.h>` |
| `unregister_filesystem()` | `vfs_fsremove()` | `<sys/mount.h>` |
| `struct super_block` | `mount_t` | `<sys/mount.h>` |
| `struct inode` | `vnode_t` | `<sys/vnode.h>` |
| `struct dentry` | (vnodes serve both roles) | `<sys/vnode.h>` |
| `struct inode_operations` | vnop descriptor entries | `<sys/vnode_if.h>` |
| `struct file_operations` | vnop descriptor entries | `<sys/vnode_if.h>` |
| `struct super_operations` | `struct vfsops` | `<sys/mount.h>` |
| `sb->s_fs_info` | `vfs_fsprivate(mp)` | `<sys/mount.h>` |
| `inode->i_private` | `vnode_fsnode(vp)` | `<sys/vnode.h>` |
| `vfs_kern_mount()` | mount helper + `vnode_lookup()` | — |
| `fsstack_copy_attr_all()` | `vnode_getattr()` + copy | `<sys/vnode.h>` |
| `genl_register_family()` | `ctl_register()` | `<sys/kern_control.h>` |
| `genlmsg_unicast()` | `ctl_enqueuedata()` | `<sys/kern_control.h>` |
| `invalidate_inode_pages2()` | `ubc_msync(UBC_INVALIDATE)` | `<sys/ubc.h>` |
| `call_usermodehelper()` | mount helper starts daemon | — |
| `kmalloc()` | `OSMalloc()` | `<libkern/OSMalloc.h>` |
| `kfree()` | `OSFree()` | `<libkern/OSMalloc.h>` |
| `spinlock_t` | `lck_spin_t` | `<kern/locks.h>` |
| `rwlock_t` | `lck_rw_t` | `<kern/locks.h>` |
| `struct completion` | `msleep()` / `wakeup()` | `<sys/proc.h>` |
| `struct work_struct` | `thread_call_t` | `<kern/thread_call.h>` |
| `module_init()` | `KMOD_EXPLICIT_DECL()` | `<mach/mach_types.h>` |
| `pr_info()` | `printf()` or `IOLog()` | `<libkern/libkern.h>` |
| `IS_ERR()` / `PTR_ERR()` | Check return code directly | — |
| `SG_IO` ioctl | `SCSITaskDeviceInterface` | `<IOKit/scsi/SCSITaskLib.h>` |
| `O_DIRECT` | `fcntl(F_NOCACHE)` | `<fcntl.h>` |
| `AF_NETLINK` | `PF_SYSTEM` / `SYSPROTO_CONTROL` | `<sys/kern_control.h>` |
