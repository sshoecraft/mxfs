# MXFS Project Status & Architecture Decision

**Date**: 2026-03-22
**Current version**: v0.3.2 (mxfs.new — to be archived)
**Prior version**: v0.14.0 (~/src/mxfs — abandoned, see handoff.md)

---

## 1. What Happened

### Original Vision
Build a multi-platform clustered filesystem (Linux, macOS, FreeBSD) that uses the
XFS v5 on-disk format. Multiple nodes share a single block device with full read/write
access. Single deliverable: mxfs.ko kernel module (Linux), with future ports.

### What We Actually Built (twice)

**~/src/mxfs (v0.14.0)** — Hand-rolled XFS format parser + custom I/O paths + DLM.
- 34K lines in libmxfs, hand-written btree engine, custom buffer cache
- Reached 29s for rsync 584MB after extensive optimization (sessions 71-73)
- XFS baseline for the same operation: 7s (4.1x overhead)
- Fundamental issue: not based on real XFS code, hand-rolled everything
- Abandoned after 73 sessions

**/src/mxfs.new (v0.3.2)** — Took xfsprogs/libxfs (the userspace utility library) +
custom I/O paths + DLM hooks.
- 78K lines of xfsprogs libxfs code + 22K lines of MXFS-native code
- Single-node fio benchmark: **45x slower than native XFS on writes**
- Root cause: xfsprogs libxfs is a format library for mkfs/fsck, NOT the kernel
  XFS I/O engine. All I/O paths (ops.c, alloc.c, inode_cache.c, xfs_adapter.c)
  were written from scratch with synchronous submit_bio_wait() for every operation.

### The Core Mistake

Neither project used the **kernel XFS code** (`~/src/linux/fs/xfs/`). The kernel XFS
has the entire performance architecture:

| Component | Kernel XFS | What We Had |
|-----------|-----------|-------------|
| Buffer cache | `xfs_buf.c` — async I/O, completion callbacks, hash-based, LRU | `xfs_adapter.c` — sync submit_bio_wait() per buffer |
| I/O mapping | `xfs_iomap.c` — iomap integration, page cache, readahead, delalloc | `ops.c` — block-by-block sync reads, no readahead |
| Transactions | `xfs_trans.c` — async commit, batched, logged | None — immediate sync flush per metadata change |
| Journal/Log | `xfs_log.c` — async, batched, in-order commit | `journal.c` — custom WAL, per-operation flush |
| File ops | `xfs_file.c` — iomap, folio, splice, DAX | `mxfs_file.c` — generic_file_read/write_iter |
| Writeback | `xfs_aops.c` — address_space_operations, writepages | No writepages, no readpages |
| Workqueues | 6 dedicated workqueues for async buffer/reclaim/GC | None — single-threaded sync I/O |

---

## 2. Benchmark Evidence

### XFS Baseline (test1 VM, Samsung 870 1.8TB, tcm_loop/CAW, 2026-03-22)

| Test | BW (MB/s) | IOPS |
|------|-----------|------|
| Seq Write 1M | 509.2 | 509 |
| Seq Read 1M | 540.3 | 540 |
| Rand Write 4K | 253.6 | 64,921 |
| Rand Read 4K | 323.9 | 82,928 |

### MXFS v0.3.2 (same setup, same day)

| Test | BW (MB/s) | IOPS | Overhead vs XFS |
|------|-----------|------|----------------|
| Seq Write 1M | 11.4 | 11 | 44.8x |
| Seq Read 1M | 39.9 | 40 | 13.5x |
| Rand Write 4K | 6.6 | 1,683 | 38.6x |
| Rand Read 4K | 6.3 | 1,619 | 51.2x |

### Old MXFS v0.9.27 on same hardware (bench.json, session 65)

| Test | BW (MB/s) | IOPS | Overhead vs XFS |
|------|-----------|------|----------------|
| Seq Write 1M | 226.3 | 226 | 2.3x |
| Seq Read 1M | 347.4 | 347 | 1.6x |
| Rand Write 4K | 8.1 | 2,069 | 24.7x |
| Rand Read 4K | 10.8 | 2,759 | 29.1x |

---

## 3. Kernel XFS Architecture (~/src/linux/fs/xfs/)

245 files, 169K lines total. Two layers:

### libxfs/ (80K lines) — Portable metadata logic
- B-tree engine (alloc, bmap, ialloc, refcount, rmap)
- On-disk format definitions and CRC verification
- AG management, inode fork operations
- Directory operations (sf, block, leaf, node)
- **This is shared between kernel and xfsprogs** — it's format logic only

### Top-level fs/xfs/ (89K lines) — Linux kernel integration
- `xfs_buf.c` (2132 lines) — Async buffer I/O, hash-based cache, semaphore locking
- `xfs_iomap.c` (2310 lines) — iomap integration for data I/O through page cache
- `xfs_log.c` (3475 lines) — Async transaction log with batched commits
- `xfs_trans.c` — Transaction engine
- `xfs_aops.c` — Address space ops (writeback, writepages)
- `xfs_file.c` — VFS file operations
- `xfs_super.c` — Mount/unmount, VFS superblock
- `xfs_icache.c` — Inode cache management
- `xfs_inode.c` — Inode operations
- `xfs_log_recover.c` — Log recovery

### Kernel API Dependencies
- iomap: 111 references (core to read/write path)
- spin_lock: 173 references
- folio: 48 references (modern page abstraction)
- mutex_lock: 32 references
- kmem_cache: 22 references (slab allocator)
- submit_bio: 11 references (surprisingly few — most I/O through iomap/xfs_buf)
- workqueue/queue_work: 18 references
- 6 dedicated workqueues at mount time

---

## 4. Architecture Options for Next Project

### Option A: Linux-Only Kernel Module (Fork Kernel XFS)

Copy `~/src/linux/fs/xfs/` to new project. Rename module to mxfs. Add DLM hooks
at strategic points. Keep the entire XFS I/O engine intact.

**DLM hook points needed:**
- `xfs_buf.c` — Flush dirty buffers on BAST, invalidate on remote write
- `xfs_inode.c` / `xfs_icache.c` — DLM lock around inode access
- `xfs_trans.c` — Coordinate transaction commits with DLM
- `xfs_log.c` — Per-node log slots, cross-node journal replay
- `xfs_super.c` — Discovery, peer mesh, DLM init at mount

**Pros:**
- Near-native XFS performance from day one (the I/O engine IS XFS)
- All the hard problems already solved (readahead, delalloc, writeback, recovery)
- Well-tested codebase (decades of production use)
- Minimizes new code — just add DLM + cluster coordination

**Cons:**
- Linux-only (no macOS, no FreeBSD)
- Maintaining a fork of kernel XFS — every kernel release needs rebasing
- DLM hooks are invasive — touching core XFS code is risky
- Tight coupling to specific kernel versions (iomap API changes, folio migration)

**Precedent:** GFS2 and OCFS2 are exactly this pattern — kernel-native clustered
filesystems with their own DLM. They just use their own on-disk formats.

### Option B: Multi-Platform with Kernel XFS I/O Engine (PAL Abstraction)

Take the kernel XFS code and decouple it from Linux kernel APIs. Replace:
- `submit_bio` → PAL block I/O (11 call sites)
- `spin_lock/mutex_lock` → PAL locks (~200 call sites)
- `kmem_cache/kzalloc` → PAL memory (~60 call sites)
- `iomap` → PAL iomap shim (111 references — this is the hard one)
- `folio` → PAL page abstraction (48 references)
- `workqueue` → PAL thread pool (~18 call sites)

**Pros:**
- Multi-platform (original vision)
- Preserves the XFS I/O architecture (unlike what we built)
- PAL abstractions can be performance-tested independently

**Cons:**
- iomap abstraction is extremely difficult — it's deeply integrated with the
  Linux page cache, folios, and writeback infrastructure
- Massive upfront effort before a single file can be read/written
- Risk of ending up with another 45x-slow PAL layer
- 200+ kernel API call sites to abstract

**The iomap problem is the dealbreaker.** iomap is not just a mapping layer — it
coordinates page cache state, writeback, hole punching, and COW. Abstracting it
means reimplementing the Linux page cache.

### Option C: Linux-Only, Loadable Kernel Module (Recommended)

Same as Option A but designed as a loadable module (not requiring kernel rebuild).
Fork fs/xfs/ into mxfs, build as out-of-tree module. Use DKMS for deployment.

**Additional considerations:**
- Can use GPL-exported kernel symbols (iomap, bio, page cache APIs)
- Module can register its own filesystem type ("mxfs")
- Both XFS and MXFS can coexist (different fs type names)
- Users format with `mkfs.mxfs` which writes the MXFS super + journal + disklock
  regions before the XFS data area (same as current layout)

---

## 5. What to Preserve from Prior Projects

### From ~/src/mxfs (v0.14.0) — see handoff.md
- DLM implementation (TCP + CAW transports) — battle-tested at 32 nodes
- Discovery (UDP multicast, 239.66.83.1:7601)
- Peer mesh (TCP connections)
- Lease system (node liveness)
- Disklock (on-disk heartbeat for CAW)
- SCSI PR (hardware fencing)
- Journal (per-node WAL slots)
- Performance optimization lessons (sessions 71-73)
- Test infrastructure (32 VMs, run_tests.sh, single/cluster/stress suites)
- Benchmark data (bench.json — VMware, KVM/iSCSI, KVM/virtio, tcm_loop)

### From /src/mxfs.new (v0.3.2) — this project
- mkfs_mxfs — format tool with MXFS super + journal + disklock + XFS data layout
- chk_mxfs — filesystem checker
- resize_mxfs — online resize
- On-disk layout (4KB MXFS super, 64MB journal, 32MB disklock, XFS data)
- DLM (refined from old project)
- Cluster coordination (refined from old project)
- Test infrastructure (updated)
- VM setup runbooks (docs/qemu_direct_caw.md, docs/qemu_tcm_loop_setup.md)
- Deployment scripts (scripts/, tools/prep_tcm_node.sh, tools/mxfs_deploy.sh)

### Test Infrastructure (shared)
- 32 VMs: test1-test32, Ubuntu 24.04, 2 vCPU / 2GB, bridged to br0
- Host: clyde (192.168.1.166 / 192.168.120.1)
- Shared storage: Samsung 870 1.8TB via tcm_loop/iblock + QEMU scsi-block
- Credentials: root / <REDACTED-ROTATED>, password file /tmp/.mxfs_pass
- NFS: 192.168.1.4:/src mounted at /src in guests
- Physical servers: pve1 (192.168.1.80), pve2 (192.168.1.81) — Proxmox, iSCSI to QNAP

---

## 6. Key Architectural Invariants (Carry Forward)

These were learned the hard way across 73+ sessions:

1. **No lock released until dirty data flushed** — BAST handler must flush dirty
   buffers, commit journal, drop cache, THEN release lock
2. **Per-inode lock caching** — Hold locks until BAST, eviction, or unmount. Never
   release after each operation.
3. **AG affinity** — `preferred_ag = node_slot % ag_count`. Reduces cross-node contention.
4. **Transport auto-detection** — Listen 3s for peers, adopt their transport. No
   peers = probe device for CAW.
5. **Sector-granularity SB writes** — XFS SB is 512B in a 4K block. Full-block
   writes clobber adjacent AG headers.
6. **Block cache flush BEFORE inode cache flush** — Prevents stale 4K cluster blocks
   from overwriting fresh 512B inodes.
7. **TCP keepalive (19s) MUST be faster than DLM lock timeout (30s)** — Otherwise
   lock timeout fires before dead node is detected.

---

## 7. Recommended Next Steps

1. Create new project directory (e.g., `/src/mxfs3/`)
2. Copy `~/src/linux/fs/xfs/` as the starting point
3. Rename module registration from "xfs" to "mxfs"
4. Get it building as an out-of-tree loadable kernel module
5. Get it mounting an XFS filesystem (no MXFS super/journal/disklock yet)
6. Benchmark — should be near-identical to native XFS
7. Add MXFS on-disk layout (super + journal + disklock prefix)
8. Add DLM hooks at xfs_buf, xfs_inode, xfs_trans, xfs_log
9. Single-node cluster test (DLM in bypass mode)
10. Multi-node cluster test
11. Port test infrastructure, runbooks, and deployment scripts from prior projects

---

## 8. Reference Files

| File | Location | Purpose |
|------|----------|---------|
| handoff.md | /src/mxfs.new/handoff.md | Complete state from old project (sessions 30-73) |
| bench.json | /src/mxfs.new/bench.json | All benchmark data across both projects |
| qemu_direct_caw.md | /src/mxfs.new/docs/ | tcm_loop + iblock CAW setup |
| qemu_tcm_loop_setup.md | /src/mxfs.new/docs/ | 9-step VM worker runbook |
| benchmark.md | /src/mxfs.new/docs/ | fio benchmark runbook |
| test-plan.md | /src/mxfs.new/docs/ | Comprehensive test matrix |
| dlm-protocol.md | /src/mxfs.new/docs/ | DLM wire protocol spec |
| architecture.md | /src/mxfs.new/docs/ | System design overview |
| prep_tcm_node.sh | /src/mxfs.new/tools/ | Automated VM prep script |
| run_tests.sh | /src/mxfs.new/tests/ | Test orchestrator |
