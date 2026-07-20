# MXFS Handoff Document

**Date**: 2026-03-22
**Version**: v0.14.0
**Author**: Claude Code sessions 30-73

This document captures the complete state of the MXFS project for handoff to a parallel implementation effort. It covers architecture, test infrastructure, session history, current instrumentation, known issues, and the performance optimization work done in sessions 71-73.

---

## 1. What Is MXFS

MXFS (Multinode XFS) is a clustered filesystem that allows multiple Linux nodes to concurrently mount and share a single XFS-formatted block device with full read/write access.

- **Single deliverable**: `mxfs.ko` kernel module
- **Language**: Portable C core (libmxfs, ~34K lines) + Linux kernel frontend
- **Not a stacking FS**: Reads/writes XFS on-disk structures directly
- **All coordination in-kernel**: No userspace daemon
- **Build**: `cd /src/mxfs && make` produces `mxfs.ko`
- **Usage**: `mkfs.mxfs /dev/sdX` then `mount -t mxfs /dev/sdX /mnt/shared`

---

## 2. Project Structure

```
/src/mxfs/
├── libmxfs/                 # Core portable library (24 files, ~34K lines)
│   ├── xfs_format.c/h       # XFS on-disk format: SB, AG headers, dinodes, extents
│   ├── extent.c/h           # Extent map management, btree serialization
│   ├── dlm.c/h              # Distributed lock manager (TCP + CAW transports)
│   ├── dlm_caw.c/h          # CAW (Compare-And-Write) DLM transport
│   ├── block_cache.c/h      # DLM-aware block cache with LRU, scatter write
│   ├── inode_cache.c/h      # DLM-aware inode cache, batched flush, get_new_exclusive
│   ├── dir_cache.c/h        # DLM-aware directory cache, shortform/block/leaf/node
│   ├── alloc.c/h            # Block/inode allocation via XFS btree cursors
│   ├── mxfs_btree.c/h       # Generic btree cursor engine
│   ├── mxfs_btree_io.c/h    # Btree block I/O
│   ├── mxfs_alloc_btree.c/h # BNO/CNT btree specialization
│   ├── mxfs_inobt.c/h       # Inode btree (inobt/finobt) specialization
│   ├── journal.c/h          # Write-ahead log (per-node slots, circular buffer)
│   ├── mount.c/h            # Mount orchestration, public API (create/mkdir/write/etc.)
│   ├── peer.c/h             # TCP peer connections
│   ├── discovery.c/h        # UDP multicast peer discovery (239.66.83.1:7601)
│   ├── lease.c/h            # Node liveness (UDP multicast, RT priority threads)
│   ├── disklock.c/h         # On-disk lock persistence (CAW DLM)
│   ├── scsipr.c/h           # SCSI Persistent Reservations (hardware fencing)
│   └── xattr.c/h            # Extended attributes (user/trusted/security/ACL)
├── pal/                     # Platform Abstraction Layer
│   ├── pal.h                # PAL interface (block I/O, threads, sockets, time, etc.)
│   ├── pal_linux_kern.c     # Linux kernel implementation (bio, kthread, kernel sockets)
│   └── pal_linux_user.c     # Linux userspace (for tools: mkfs, chk, resize)
├── frontend/linux/          # Linux VFS glue (5 files)
│   ├── mxfs_super.c         # mount/umount, sync_fs, show_options
│   ├── mxfs_inode.c         # inode_ops: lookup, create, mkdir, unlink, setattr, d_revalidate
│   ├── mxfs_file.c          # file_ops: read_iter, write_iter, mmap, fallocate, fsync, splice
│   ├── mxfs_dir.c           # readdir
│   └── mxfs_internal.h      # VFS private structs
├── include/mxfs/            # Public headers
│   ├── mxfs_common.h        # Lock modes, resource IDs, mount options, FNV-1a
│   ├── mxfs_dlm.h           # DLM wire protocol structs
│   └── mxfs_super.h         # On-disk MXFS superblock (4KB, before XFS data)
├── tools/                   # Userspace tools
│   ├── mkfs_mxfs.c          # Format tool (~400 lines, standalone)
│   ├── chk_mxfs.c           # Filesystem checker (btree walk, inode spot-check)
│   ├── resize_mxfs.c        # Online resize
│   ├── prep_node.sh         # Node prep for iSCSI-based VMs
│   ├── prep_tcm_node.sh     # Node prep for tcm_loop VMs (CAW)
│   ├── mxfs_deploy.sh       # Deploy module to remote nodes
│   └── mxfs_sshpass.sh      # SSH wrapper with password file
├── tests/                   # Test framework
│   ├── run_tests.sh         # Master orchestrator (runs from dev machine)
│   ├── mxfs_test.sh         # Per-node executor (runs on test node via SSH)
│   ├── lib/common.sh        # Assertions, logging, test lifecycle
│   ├── lib/cluster.sh       # SSH wrappers, barriers, mount helpers
│   ├── single/              # 12 single-node tests
│   ├── cluster/             # 11 cluster tests (cross-node coherency)
│   └── stress/              # 6 stress tests
├── packaging/               # DKMS .deb/.rpm, PVE storage plugin
├── docs/                    # Documentation and runbooks
│   ├── architecture.md      # System design overview
│   ├── qemu_tcm_loop_setup.md  # Worker runbook: VM prep with CAW
│   ├── qemu_direct_caw.md   # How tcm_loop + iblock provides CAW
│   ├── test-plan.md         # Comprehensive test matrix
│   ├── dlm-protocol.md      # DLM wire protocol specification
│   └── (discovery.md, perf.md, benchmark.md, etc.)
├── Kbuild                   # Kernel build system integration
├── Makefile                 # Top-level: make, make clean, make package
├── VERSION                  # Current version string (0.14.0)
└── .claude/awareness/       # 3-layer awareness system for Claude Code
    ├── structural-map.md    # 705 functions across 61 files
    └── subsystems/          # 7 subsystem docs (xfs-format, dlm, caches, etc.)
```

---

## 3. Architectural Invariants

These MUST NEVER be violated. Breaking them causes silent corruption.

1. **No lock released until dirty data flushed**: BAST handler must flush dirty blocks, commit journal, drop cache entries, THEN release the lock.

2. **Per-inode lock caching**: Locks held until BAST, eviction, or unmount. Never release after each operation.

3. **AG affinity**: `preferred_ag = node_slot % ag_count`. Reduces cross-node contention.

4. **Three-layer fencing (CAW only)**: SCSI PR + disk heartbeat + DLM. TCP DLM skips SCSI PR (uses network fencing).

5. **DLM transport auto-detection**: Listen 3s for peers, adopt their transport. No peers = probe device for CAW.

6. **Journal per-node**: Dedicated slot per node. Survivor replays dead node's journal.

7. **Sector-granularity SB writes**: XFS SB is 512B in 4K block with AGF/AGI. Full-block writes clobber adjacent headers.

8. **Block cache flush BEFORE inode cache flush** (added session 73): alloc.c writes inode cluster initialization blocks (4K) to block_cache. Inode cache writes individual 512B inodes directly. If block_cache flushes AFTER inode cache, stale 4K blocks overwrite fresh inode data.

---

## 4. DLM Transports

| Transport | Mechanism | Max Tested | Notes |
|-----------|-----------|-----------|-------|
| **CAW** | SCSI Compare-And-Write on shared device | 32 nodes | No master node. Better scaling. Default when device supports it. |
| **TCP** | Network-based, per-resource lock mastering | 32 nodes | Single lock master per resource = serial bottleneck. 7.7x write spread at 4+ nodes. |

Auto-detection: mount listens for peer announces (3s), adopts their transport. If no peers, probes device with CAW operation.

---

## 5. On-Disk Layout

```
[ MXFS Super (4KB) ][ Journal (64MB, 64 slots) ][ Disklock (32MB) ][ XFS Data (rest) ]
```

- **MXFS Super** (`struct mxfs_ondisk_super`): magic, version, UUID, offsets/sizes for each region
- **Journal**: Per-node circular buffer slots (2048 sectors = 1MB each). Write-ahead log for crash recovery.
- **Disklock**: On-disk heartbeat sectors for CAW DLM node liveness detection.
- **XFS Data**: Standard XFS v5 filesystem created by `mkfs.mxfs` using libxfs routines.

The XFS data area is accessed via a cloned bdev handle with `base_offset = xfs_data_offset`. All block numbers in libmxfs are relative to the XFS data area start.

---

## 6. Key Data Flows

**Write path**: VFS write -> inode EX lock (cached or acquire) -> allocate blocks via AG btrees -> write data to page cache -> (on sync/BAST) flush dirty blocks -> journal commit -> release if BAST

**Read path**: VFS read -> inode PR lock (cached or acquire) -> resolve extent map -> read blocks from cache (or disk) -> return data -> hold lock (no release)

**Mount path**: module init -> fill_super -> read SB -> init PAL -> init DLM -> discovery -> peer mesh -> lease start -> journal replay -> init caches -> init alloc -> ready

**sync_fs path** (v0.14.0): dir_cache_flush_all -> flush_superblock_counters -> block_cache_flush -> inode_cache_flush_all (batched: serialize -> compound journal -> scatter write -> bdev_flush) -> journal_flush -> bdev_flush

**Node failure (CAW)**: heartbeat timeout (~62s) -> SCSI PR check -> DLM purge dead node's locks -> journal replay -> surviving nodes resume

---

## 7. Test Infrastructure

### 7.1 VM Environment

- **32 VMs**: test1-test32, Ubuntu 24.04, 2 vCPU / 2GB RAM, bridged to br0 (192.168.120.0/24)
- **Host**: clyde (192.168.1.166 / 192.168.120.1)
- **Credentials**: root / <REDACTED-ROTATED>
- **Password file**: `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass`
- **SSH**: `/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "CMD"`

### 7.2 Shared Storage (tcm_loop + CAW)

The VMs share a single block device via SCSI passthrough. CAW (Compare-And-Write) is emulated by LIO's iblock layer.

**Chain**: Physical SSD (`/dev/sda`, Samsung 870 1.8TB) -> LIO iblock backstore -> tcm_loop (local SCSI loopback) -> `/dev/sdc` on host -> QEMU `scsi-block` passthrough -> `/dev/sda` in guest

**Setup** (documented in `docs/qemu_direct_caw.md`):
```bash
modprobe tcm_loop
targetcli /backstores/block create name=ssd_870 dev=/dev/sda
targetcli /loopback create naa.50000000000000a1
targetcli /loopback/naa.50000000000000a1/luns create /backstores/block/ssd_870
# /dev/sdc appears on host
```

**VM requirements**:
- `<disk type='block' device='lun'>` (NOT `device='disk'`)
- `<source dev='/dev/sdc'/>`
- virtio-scsi controller
- AppArmor `capability sys_rawio` in VM profile
- System libvirt (`sudo virsh`), NOT user session

### 7.3 Worker Runbook

`docs/qemu_tcm_loop_setup.md` — 9-step runbook for preparing a VM:

1. Verify VM XML (device='lun', source=/dev/sdc, virtio-scsi)
2. Ensure VM running (handle stale QEMU, permission issues)
3. Wait for SSH
4. Mount NFS (192.168.1.4:/src -> /src)
5. Verify SCSI device in guest
6. Verify CAW (`sg_compare_and_write`)
7. Load MXFS module (`insmod /src/mxfs/mxfs.ko`)
8. Install benchmark deps (fio, mosquitto-clients)
9. Report PREP_OK or PREP_FAIL

Alternative: `tools/prep_tcm_node.sh` — automated version (runs ON the guest).

### 7.4 Test Suites

**Run from dev machine (clyde)**:
```bash
# Single-node (test1 only)
MXFS_TESTS_DIR=/src/mxfs/tests tests/run_tests.sh --nodes 1 --phase single --device /dev/sda --pass-file /tmp/.mxfs_pass

# 4-node cluster
MXFS_TESTS_DIR=/src/mxfs/tests tests/run_tests.sh --nodes 4 --phase cluster --device /dev/sda --pass-file /tmp/.mxfs_pass

# Stress (32 nodes)
MXFS_TESTS_DIR=/src/mxfs/tests tests/run_tests.sh --nodes 32 --phase stress --device /dev/sda --pass-file /tmp/.mxfs_pass
```

**Single-node tests** (12): mount, mkdir, write_read, stat, rename, unlink, symlink, touch, permissions, large_file, many_files, nested_dirs

**Cluster tests** (11): concurrent_mkdir, concurrent_touch, concurrent_write, cross_visibility, cross_write_read, dir_stress, discovery, large_file_integrity, rename_visibility, sequential_consistency, tcp_mesh, unlink_visibility

**Stress tests** (6): file_storm, large_dir, many_dirs, metadata_storm, mixed_workload, throughput

### 7.5 Physical Test Environment (Proxmox)

- **pve1** (192.168.1.80): Xeon W3520 4-core, 12GB, Debian 13, kernel 6.17.2-1-pve
- **pve2** (192.168.1.81): Xeon W3550 8-core, 12GB, same
- **Storage**: QNAP TS-453 Pro (192.168.1.4), 3x 20GB iSCSI LUNs, gigabit Ethernet
- **NFS**: 192.168.1.4:/src -> /src
- **Password**: /tmp/.proxmox_pass (<REDACTED-ROTATED>)
- **Note**: QNAP does NOT support SCSI CAW. Use TCP DLM transport on QNAP.

---

## 8. Session History (Sessions 30-73)

### Session 30 (v1.7.0) — DLM Transport Auto-Detection

- **Bug 104**: Joining TCP cluster with CAW transport -> 30s timeout. SCSI PR on QNAP -> reservation conflicts blocking all I/O.
- **Fix**: `MXFS_DLM_TRANSPORT_AUTO` default. Listen for peers 3s, adopt transport. Probe device for CAW. Skip SCSI PR for TCP DLM.
- **Discovery**: Added `dlm_transport` field to announce packet.
- **Tested**: 2-node (clyde + z440), cross-node read/write PASS.

### Session 31 (v1.7.1) — Packaging + PVE Plugin

- `make package` auto-detects .deb/.rpm. DKMS source + tools + modules-load.d.
- PVE storage plugin: `pvesm add mxfs <name> --blockdevice /dev/sdX --shared 1`
- **Bug 105**: TCP keepalive was 90s detection, DLM timeout 30s. Fixed: 19s detection.
- iSCSI auto-start + fstab on all physical nodes.

### Session 32 (v1.7.2) — Grant Epoch Fix

- **Bug 106**: DLM grant epoch mismatch at 3+ nodes with incremental joins. Master used its own epoch in grants, but stale-grant filter compared against requester's epoch. Valid grants silently discarded -> 30s timeouts.
- **Fix**: Echo requester's epoch in grant messages.
- **Bug 107**: TCP disconnect didn't remove dead node from active_nodes. Fix: `remove_node()` for TCP DLM in `peer_disconnect_cb()`.
- **Bug 108**: `disklock_expire_cb` reported wrong node_id (0 instead of actual).

### Session 33 (v1.7.3) — Deployment Lessons

- Remote build: use `make -C /src/mxfs` not `cd /src/mxfs && make`
- Must unmount ALL nodes before upgrading module.

### Session 34 — Production Readiness

- All Tier 1/2/3 features implemented: B+tree extents, mknod, long symlinks, xattrs, POSIX ACLs, mmap, fallocate, POSIX locks, SEEK_HOLE/DATA, rename flags, mount options, splice, freeze/thaw, FINOBT, chk_mxfs improvements, man pages, log cleanup.
- Only version renumbering + final test pass remain for v1.0.0.

### Sessions 40-59 — Bug Fixes

- Bugs 119-137 fixed. Key issues: btree allocation bugs, counter drift (Bug 129), superblock clobber (Bug 132-134), membership change race (Bug 135), guard map (Bug 136), cntbt duplicates (Bug 137).
- See `memory/bugfix-history.md` for full details.

### Sessions 60-62 — Btree Engine Replacement (ABANDONED)

- Attempted replacing alloc.c hand-rolled btree with XFS cursor engine.
- 8 new files, alloc.c rewrite from 4937 to ~1870 lines.
- **CAUSED REGRESSION**: concurrent PVE VM builds broke (stale dir cache, BASTs not firing).
- Source rolled back to v0.9.18. **DO NOT reattempt unless explicitly asked.**

### Session 63 — VM Builds + Kernel Compat

- Bug 140: io_uring race — added per-inode mutex.
- Bug 141: stale blocks — block zeroing on allocation.
- Kernel 6.12 compat: three-way page/folio split in mxfs_file.c.

### Session 64 (v0.3.0) — Complete Rewrite

- Full rewrite using real XFS BNO/inobt btree walking.
- Single-node: 19/19 acceptance tests PASS.
- Cluster: 4-node TCP DLM operational, cross-node file visibility + data integrity.

### Session 71 — Performance Investigation

**Root cause identified**: 43,000 small synchronous writes at ~550us each (iSCSI round-trip). XFS does 1,400 large writes. IOPS count is the bottleneck.

**Failed approaches**: Journal batching (checkpoint frequency defeated it), FUA removal (no latency difference on QNAP).

**Planned fix**: Write-back metadata caching — route all metadata through block_cache, flush only on BAST/sync.

### Session 72 — Write-Back Caching (60 min -> 60 sec)

1. Removed 18 eager `flush_inode` calls. Inodes stay dirty until BAST/sync/eviction.
2. Dir block writes routed through block_cache (7 FUA -> block_cache conversions).
3. Compound AG journal transactions (74,424 commits -> 8,770).
4. Dir cache yield quantum fix (dir flushes: 8,771 -> 186).
5. Eviction safety: `flush_dir_cache_ino` before `flush_inode_to_disk`.
6. Async scatter write for block_cache (16 concurrent BIOs).

**Result**: rsync 584MB: 6 minutes -> 60 seconds.

### Session 73 — Async Batched I/O (60 sec -> 29 sec)

1. **Batched async inode flush**: `serialize_inode()` extracted. `flush_all` does: serialize all -> compound journal txns (8,770 -> 18) -> scatter write -> single bdev_flush. Inode phase: 10.5s -> 1.1s.
2. **Skip disk read for new inodes**: `get_new_exclusive()` avoids loading zeros from disk for freshly allocated inodes. Sets dinode magic (0x494e) in raw_buf. Create getex: 5.3s -> 12ms.
3. **Block cache readahead**: 8 contiguous blocks per cache miss. Misses: 16,851 -> 6,846.
4. **Cache size increase**: Inode 8K -> 32K. Block 4K -> 16K.
5. **sync_fs reorder**: block_cache flush BEFORE inode flush (prevents cluster block clobber).
6. **Block cache clobber bug**: alloc.c writes 4K inode cluster blocks to block_cache during chunk init. If block_cache flushes after inode scatter write, stale 4K overwrites fresh 512B inodes. Fixed by pre-write invalidation + sync_fs reorder.

**Result**: rsync 584MB: 60 seconds -> 29 seconds. XFS baseline: 7 seconds.

---

## 9. Current Instrumentation (v0.14.0)

All instrumentation is in the code and harmless (DEBUG level or INFO on specific events):

### inode_cache.c
- `serialize_inode`: magic validation with log on set
- `flush_all`: phase timing (serialize, journal, scatter, invalidate, total)
- `flush_all`: first 3 inodes log raw magic/mode/offset/len
- `flush_inode_to_disk`: ino 128 lifecycle logging
- `evict_one`: ino 128 state/format logging
- `mxfs_inode_cache_put`: BAST yield quantum logging
- `journal_commits` counter per inode cache instance

### block_cache.c
- `flush_dirty_blocks` counter
- `CACHE_MISS_READAHEAD` constant (currently 8)

### dir_cache.c
- `ADD/FLUSH/RELOAD` logging for ino 128
- `add_entry` timing (getex_ms, put_ms, count, flushes)
- Flush breakdown (sf/block/leaf counts and ms)
- Dirty discard detector in `free_cached_dir`

### mount.c
- `sync_fs` phase timing (dir, inode, sb, bcache, jflush, devflush, total)
- `create` breakdown (alloc, getex, init, diradd, total, count)
- `mkdir`/`write` timing
- iomap stats (alloc, mapped, mapped_blocks, avg_len)
- Alloc timing (alloc_inode ms/count, alloc_block ms/count)

### alloc.c
- Per-site journal commit counters (inode_chunk, inode_alloc, inode_free, agfl, block_alloc, block_free, revoke)
- AG transition counter, flush errors, cntbt desyncs, alloc retries

### pal_linux_kern.c
- Per-bdev I/O stats (writes, bytes, FUA writes/bytes, flushes, latency ns)

### frontend/linux/mxfs_file.c
- iomap path counters (alloc, mapped, mapped_blocks)

---

## 10. Hypotheses & Conclusions

### Confirmed Hypotheses

1. **Synchronous FUA writes are the bottleneck** (Session 71-72): 43,000 small writes at 550us each. Fix: write-back caching. Result: 6min -> 60s.

2. **Per-inode FUA in flush_all is the sync_fs bottleneck** (Session 73): 8,770 x FUA = 10.5s. Fix: scatter write + single flush. Result: 10.5s -> 1.1s.

3. **Unnecessary disk reads for new inodes** (Session 73): get_exclusive reads zeros from disk for freshly allocated inodes. Fix: get_new_exclusive. Result: 5.3s -> 12ms.

4. **Block cache miss rate** (Session 73): 16,851 misses from single-block reads. Fix: 8-block readahead. Result: 59% fewer misses.

5. **Block cache clobber** (Session 73): alloc.c inode cluster init blocks (dirty 4K in block_cache) overwrite fresh 512B inode writes during block_cache_flush. Fix: pre-write invalidation + sync_fs reorder.

### Current Hypothesis (Open)

**Block cache synchronous reads during file creation compete with data writeback on the iSCSI device, causing 4.3x slower throughput vs XFS.**

- 6,846 block cache misses x ~600us = ~4.1s pure blocking I/O
- Each miss does `submit_bio_wait` (4KB read), blocking thread and device queue
- XFS uses kernel page cache for metadata (readahead, merging, scheduling built-in)
- MXFS uses separate block_cache with direct `submit_bio_wait` reads

Evidence: iostat shows 650-860 r/s at 4KB during create phase, 0% merging, 80% util. XFS shows 0 reads, 300-500KB writes, 93% merging, 100MB/s.

### Potential Next Steps (Unimplemented)

1. **Page-cache-based metadata I/O**: Replace block_cache direct reads with `read_mapping_page()`. Biggest potential win (~15-20s).
2. **Btree cursor caching**: Remember last leaf position, advance instead of re-traverse. Medium complexity, ~2-4s savings.
3. **Bulk inode allocation**: Allocate 64 inodes per btree traversal instead of 1.

---

## 11. Known Issues

### Current (v0.14.0)

1. **Multi-node testing incomplete on tcm_loop**: 4-node coherence passed (manual test), but stale SCSI PR reservations from session debugging left environment dirty. Need clean environment to run full cluster test suite.

2. **Inode cache eviction ENOENT** (single-node only): When cache < total inodes, directory inode eviction during file creation causes subsequent creates to return ENOENT. Fixed by increasing cache to 32K, but root cause (VFS dentry invalidation race during eviction) needs investigation for memory-constrained systems.

3. **SCSI PR cleanup**: Stale reservations from aborted multi-node sessions can persist. Clear with `sg_persist --out --preempt --param-rk=STALE_KEY --param-sark=0 --prout-type=5 /dev/sdX`.

### Long-Standing

- Force `rmmod` corrupts kernel state (requires reboot)
- iSCSI device name non-deterministic (`prep_node.sh` / `prep_tcm_node.sh` auto-detect)
- Root dir EX lock contention at 8+ nodes (inherent: modifications MUST take EX)
- PVE plugin pvesm+pvestatd spin 100% CPU if mxfs mount hangs

---

## 12. Performance Baselines

### Single-Node I/O (Session 27, QNAP iSCSI)

| Test | Raw XFS | MXFS | Ratio |
|------|---------|------|-------|
| New file write | 63-82 MB/s | 79-83 MB/s | 1.0x (faster, no journal) |
| Overwrite | 88 MB/s | 83 MB/s | 0.94x |
| Cold read 100MB | 84 MB/s | 80 MB/s | 0.95x |
| Cold read 500MB | 101 MB/s | 98 MB/s | 0.97x |

### Multi-Node Write Throughput (Session 28, QNAP iSCSI)

| Nodes | v1.5.0 Agg Write | v1.6.0 Agg Write |
|-------|-----------------|-----------------|
| 2 | 392 MB/s | 464 MB/s |
| 4 | 465 MB/s | 438 MB/s |
| 8 | 1098 MB/s | 1714 MB/s |

### rsync Benchmark (Session 73, Samsung SSD via tcm_loop)

| Config | rsync + sync |
|--------|-------------|
| XFS | 7.0s |
| MXFS v0.13.0 (session 72) | 60s |
| MXFS v0.14.0 (session 73) | 29s |

---

## 13. Build & Deploy Quick Reference

```bash
# Build
cd /src/mxfs && make

# Specific kernel
make KDIR=/usr/src/linux-headers-$(uname -r)

# Clean rebuild
make clean && make

# Deploy (via NFS — VMs mount /src from 192.168.1.4)
# Module at /src/mxfs/mxfs.ko is visible to all VMs immediately after build

# Format
echo y | /src/mxfs/tools/mkfs_mxfs /dev/sdX

# Mount
mount -t mxfs /dev/sdX /mnt/shared

# Unmount (MUST unmount ALL nodes before upgrading module)
umount /mnt/shared

# Load/unload module
modprobe libcrc32c  # dependency
insmod /src/mxfs/mxfs.ko
rmmod mxfs

# Test setup (tcm_loop)
modprobe tcm_loop
targetcli /backstores/block create name=ssd_870 dev=/dev/sda
targetcli /loopback create naa.50000000000000a1
targetcli /loopback/naa.50000000000000a1/luns create /backstores/block/ssd_870
chmod 666 /dev/sdc
# Then use docs/qemu_tcm_loop_setup.md runbook for each VM

# Run tests
echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass
MXFS_TESTS_DIR=/src/mxfs/tests tests/run_tests.sh --nodes N --phase PHASE --device /dev/sda --pass-file /tmp/.mxfs_pass
```

---

## 14. Files Modified in Session 73

From v0.13.0 baseline:

| File | Changes |
|------|---------|
| `VERSION` | 0.13.0 -> 0.14.0 |
| `libmxfs/inode_cache.c` | `serialize_inode()`, batched `flush_all`, `get_new_exclusive()` (with dinode magic 0x494e), pre-write block_cache invalidation, `flush_all_simple()` (debug), phase timing instrumentation |
| `libmxfs/inode_cache.h` | `get_new_exclusive()` declaration, `flush_all_simple()` declaration, cache size 8192 -> 32768 |
| `libmxfs/block_cache.c` | `CACHE_MISS_READAHEAD` (8-block readahead on cache miss) |
| `libmxfs/block_cache.h` | Cache size 4096 -> 16384 |
| `libmxfs/mount.c` | `get_new_exclusive` wired into create/mkdir/mknod/symlink, sync_fs reorder (block_cache before inode_cache) |

---

## 15. Awareness System

The project uses a 3-layer awareness system for Claude Code sessions:

1. **Layer 1**: `CLAUDE.md` — always loaded. Architecture, invariants, routing table.
2. **Layer 2**: `.claude/awareness/subsystems/*.md` — 7 docs, one per subsystem.
3. **Layer 3**: `.claude/awareness/structural-map.md` — 22K tokens, 705 functions across 61 files.

**Routing table** (from CLAUDE.md):

| Area | Load This Doc |
|------|---------------|
| XFS format, extents | `subsystems/xfs-format.md` |
| DLM, locks, BAST | `subsystems/dlm.md` |
| Block/inode/dir cache | `subsystems/caches.md` |
| Allocation, btrees | `subsystems/alloc.md` |
| Peer, discovery, lease, journal | `subsystems/cluster.md` |
| Mount, PAL, VFS ops | `subsystems/platform-vfs.md` |
| mkfs, chk, tests, packaging | `subsystems/tooling.md` |

---

## 16. For the v5 XFS Glue Parallel Effort

Key context for someone working on XFS v5 format compatibility:

1. **MXFS reads/writes XFS on-disk format directly**. It is NOT a stacking filesystem. It implements its own XFS format parser in `libmxfs/xfs_format.c`.

2. **XFS v5 features used**: CRC32C on all metadata (dinodes, AGF, AGI, btree nodes), UUID validation, FINOBT (free inode btree), 176-byte dinode core (vs 96 for v2).

3. **XFS v5 features NOT used**: reflink, rmap btree, reverse-mapping, realtime subvolume.

4. **Extent serialization**: Supports both inline (FMT_EXTENTS, up to 21 extents in dfork) and B+tree (FMT_BTREE, unlimited via leaf/node blocks). Serialization in `extent.c`: `mxfs_extent_map_serialize_to_fork()` (inline), `mxfs_extent_map_serialize_to_btree()` (B+tree).

5. **Directory formats**: All 4 XFS dir2 formats implemented: shortform (FMT_LOCAL, inline in inode), single-block, leaf, node. Implemented in `dir_cache.c`: `flush_shortform_dir()`, `flush_block_dir()`, `flush_leaf_dir()`.

6. **mkfs**: `tools/mkfs_mxfs.c` is standalone (~400 lines). It creates a minimal XFS v5 filesystem natively (writes SB, AGF, AGI, AGFL, btree roots, root inode). Does NOT use libmxfs.

7. **The PAL isolates all OS-specific code**: If you're changing format parsing, you only need libmxfs files. If you're changing I/O patterns, you need PAL + frontend.
