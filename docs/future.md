# MXFS Future Work

## Priority 1 — Production Readiness

### CAW through device-mapper / multipath
**Status**: Not started
**Impact**: High — blocks CAW DLM in any production SAN environment

The CAW (Compare-And-Write) implementation in `pal/pal_linux_kern.c` walks `bdev → gendisk → parent` and expects a `scsi_device` directly. When multipath (device-mapper) is in the path, the parent is a DM device, not a SCSI device. `scsi_is_sdev_device()` returns false, CAW returns `-EOPNOTSUPP`, and auto-detect falls back to TCP DLM.

SCSI PR already works through multipath because it uses the kernel's `pr_ops` interface, which device-mapper forwards transparently. CAW bypasses this by sending a raw SCSI CDB.

**Fix approach**: Walk the DM target stack to find the underlying SCSI device. Device-mapper exposes `dm_table_get_target()` and `dm_get_dev_t()`. For multipath specifically, iterate `dm_target → multipath → path_group → path → scsi_device`. Alternatively, use the `bdev_kobj()` / sysfs slave walk that `sg_io` uses.

**Files**: `pal/pal_linux_kern.c` — `mxfs_pal_bdev_compare_and_write()` (line ~1772)

**Test**: Mount via `/dev/mapper/mpathX` with multipathd running, verify `dmesg` shows `dlm_transport=caw` instead of falling back to `tcp`.

### fallocate / sparse file support
**Status**: Not started
**Impact**: High — PVE VM disk images use fallocate for thin provisioning

PVE creates VM disk images using `fallocate()` on sparse files. MXFS needs to handle `FALLOC_FL_KEEP_SIZE` and `FALLOC_FL_PUNCH_HOLE` correctly across nodes. This was the issue that caused the move to mxfs.old — but root cause was VM writeback cache (`cache=writeback`), not fallocate itself. Needs verification with `cache=none`.

**Files**: `frontend/linux/mxfs_file.c` — `mxfs_kern_file_fops.fallocate`

### Speculative preallocation tuning
**Status**: Implemented (256 blocks) but may need adjustment
**Impact**: Medium — affects sequential write performance

Current: `mxfs_alloc_file_block()` preallocates 256 contiguous blocks per call. Session 18 showed 11x write regression without this. May need adaptive sizing based on file size or write pattern.

**Files**: `libmxfs/inode_cache.c`

## Priority 2 — Performance

### Write straggler / AGF lock contention
**Status**: Known issue, not addressed
**Impact**: Medium — last-mounted node consistently 3-5x slower on writes

AG affinity (`preferred_ag = node_slot % ag_count`) helps but doesn't eliminate contention when multiple nodes allocate simultaneously. The last node to mount gets the most contended AG. Session 17/19 documented this pattern.

**Possible fixes**:
- Per-node AG reservation (each node gets exclusive AGs)
- Lazy AGF lock (batch multiple allocations under one lock)
- Background preallocation thread

### Read-ahead for extent maps
**Status**: Not started
**Impact**: Low-medium — affects sequential read on cold cache

Currently each `mxfs_get_block()` call resolves one extent. For sequential reads, prefetching the next N extents would reduce extent-map lookup overhead.

## Priority 3 — Resilience

### Journal checkpoint on clean unmount
**Status**: Not started
**Impact**: Low — reduces replay time after unclean shutdown

Write a CHECKPOINT entry to the journal on clean unmount so replay can skip already-committed transactions.

### Fencing timeout tuning
**Status**: Current defaults work but not validated at scale
**Impact**: Medium at large scale

CAW heartbeat timeout (~62s) and lease DEAD threshold (150 missed × 400ms = 60s) need validation at 16+ nodes where iSCSI congestion can cause false positives.

## Priority 4 — Platforms

### macOS / FreeBSD port
**Status**: Design doc exists (`docs/macos.md`, `docs/future.md` old version)
**Impact**: Feature expansion

PAL is designed for this. Needs VFS frontend for each platform.

### RHEL 8 / kernel 4.18 support
**Status**: Not started
**Impact**: Low — RHEL 8 EOL approaching

Would require additional `MXFS_EFFECTIVE_VERSION` guards for 4.18-era APIs.
