# MXFS project history

How MXFS got here: four predecessor codebases, the benchmark evidence that ended
them, the 2026-03-22 decision to fork kernel XFS rather than keep hand-writing a
filesystem, and the bug history of everything before v5.

This is a record. For how the system is meant to work now, read the design
documents beside it — `architecture.md`, `dlm-protocol.md`,
`ag-metadata-coherency.md`. For what changed in the source, read `CHANGELOG.md`.

## The predecessors: mxfs.1 through mxfs.4

### Previous Attempts

#### mxfs.1 (~/src/mxfs.1) — v0.14.0
- Custom XFS format handling, 34K lines in libmxfs
- Hand-written block/inode/dir caches, custom btree engine, custom alloc.c
- Single-node: 19/19 PASS, 103 bugs fixed, 32-node CAW DLM tested
- **Problem**: rsync 29s vs native XFS 7s. Root cause: all metadata I/O was synchronous submit_bio_wait. Session 71 found 43,000 small sync writes at ~550us each. Sessions 72-73 added writeback caching and batched flush, cutting 60s→29s, but still 4x native XFS.
- **Key asset**: DLM (dlm.c 84K, dlm_caw.c 48K) — battle-tested at 32 nodes

#### mxfs.2 (~/src/mxfs.2) — v0.6.0→v0.9.19
- Started as stacking FS wrapping XFS at VFS layer
- Later morphed into btree rewrite using XFS cursor engine
- **Problem**: Scope creep, no clear direction, abandoned

#### mxfs.3 (~/src/mxfs.3 = /src/mxfs.new) — v0.3.2
- Attempted to use xfsprogs/libxfs as the XFS implementation
- **CRITICAL MISTAKE**: xfsprogs/libxfs is the USERSPACE format library for mkfs/fsck/resize. It is NOT the kernel XFS code. Has no iomap, no xfs_buf async I/O, no page cache, no writeback.
- Result: 45x slower than native XFS (11.4 MB/s vs 509 MB/s)
- project.md documents the full analysis

#### mxfs.4 (within mxfs.2, sessions 60-62)
- Tried replacing alloc.c with XFS cursor-based btree engine from libxfs
- **CAUSED REGRESSION**: concurrent PVE VM builds broke (stale dir cache, BASTs not firing)
- Rolled back to v0.9.18

### Why v5 Will Work

v5 uses the ACTUAL Linux kernel XFS source code from ~/src/linux/fs/xfs/ (kernel 6.19.0-rc0). This gives us:
- xfs_buf.c — async buffer cache with LRU, writeback, I/O scheduling
- xfs_iomap.c — iomap integration for buffered/direct I/O
- xfs_log.c/xfs_log_cil.c — write-ahead log with CIL batching
- xfs_aops.c — address space ops (page cache integration)
- xfs_icache.c — inode lifecycle, reclaim, writeback

These are the exact subsystems that made native XFS 4x faster than our custom code.

**How to apply:** Never attempt to reimplement XFS I/O paths. Use the kernel code as-is. DLM hooks go INTO the existing XFS infrastructure (xfs_buf, xfs_icache), not around it.

## Where the prior trees live, and what is in them

`~/src/mxfs.1/`, `~/src/mxfs.2/`, `~/src/mxfs.3/` contain the prior
project iterations. v5 (current `/src/mxfs`) was started fresh against
kernel XFS source and did NOT carry forward the awareness docs, bug
journals, or scaling benchmarks from these directories.

**Why this matters:** Sess20-27 of v5 kept "discovering" issues that are
already characterized in mxfs.1 prior art — TCP DLM scale limits, BAST
delivery semantics, lease-vs-disconnect interaction, peer reconnect
cooldowns, membership stabilizer, etc. v5's empty `.claude/awareness/`
directory is a major contributing factor to the circular debugging.

**How to apply:** Before debugging a v5 cluster-coordination issue, check
whether the same class of issue was already analyzed in prior art. Use
these as starting points:

- `~/src/mxfs.1/.claude/awareness/structural-map.md` — populated structural
  map (functions, calls, types). v5's equivalent does not exist yet.
- `~/src/mxfs.1/.claude/awareness/subsystems/cluster.md` — DLM/lease/peer/
  disklock subsystem doc.
- `~/src/mxfs.1/.claude/awareness/subsystems/dlm.md` — DLM-specific deep dive.
- `~/src/mxfs.1/.claude/awareness/subsystems/platform-vfs.md` — PAL/VFS deep
  dive.
- `~/src/mxfs.1/handoff.md` — last-session handoff at end of mxfs.1.
- `~/src/mxfs.1/README.md` — top-level architectural summary, transport
  comparison table.
- `~/src/mxfs.1/docs/architecture.md` — DLM Transport Scalability section
  (line ~440), serial-bottleneck explanation.
- `~/src/mxfs.1/docs/dlm-protocol.md` — protocol spec.
- `~/src/mxfs.1/docs/perf.md` — performance characterization.
- `~/src/mxfs.1/bench.json` — actual benchmark numbers (1.01x CAW vs 7.7x
  TCP write spread).
- `~/src/mxfs.1/scale_tests_session10.txt` — 6/8/16-node CAW test logs.
- `~/src/mxfs.1/scale_test_6node.txt` — 6-node CAW BAST delivery failure
  evidence.
- `~/src/mxfs.1/libmxfs/*.md` — per-module changelogs (peer.md, dlm.md,
  mount.md, inode_cache.md, lease.md, dir_cache.md). Contains hundreds of
  bug fixes with root-cause writeups.
- `~/src/mxfs.1/pal/pal.md` — PAL TCP tuning history (TCP_USER_TIMEOUT,
  buffer sizes, sndtimeo).
- `~/src/mxfs.2/NEWSYS.md` — mxfs.2 redesign notes.
- `~/src/mxfs.3/journal.md`, `~/src/mxfs.3/project.md` — mxfs.3 design.

**Plan:** User said (sess28) "we will run awareness here but not yet — for
now research this." Meaning: read the prior-art corpus first, build the
mental model from documented evidence, then later bootstrap v5's own
awareness with the carry-forward facts.

## 2026-02-19 — the performance session (mxfs v2)

### Summary
Optimized mxfs v2 I/O from 2.1/3.8 MB/s to near-native single-node and working 4-node cluster.

### Performance Results

#### Single-Node (vs raw XFS)
| Test | Raw XFS | MXFS | Notes |
|------|---------|------|-------|
| New file write | 63-82 MB/s | 79-83 MB/s | mxfs faster (no journal) |
| Overwrite | 88 MB/s | 83 MB/s | 5.7% overhead |
| Cold read 100MB | 84 MB/s | 80 MB/s | 95% of native |
| Cold read 500MB | 101 MB/s | 98 MB/s | 97% of native |

#### Multi-Node
| Nodes | Write | Read/node | Dir visibility | Clean unmount |
|-------|-------|-----------|----------------|---------------|
| 1 | 79 MB/s | 98 MB/s | N/A | PASS |
| 3 | 38-50 MB/s | 60 MB/s | PASS | PASS |
| 4 | 38 MB/s | 60 MB/s | PASS (4/4) | PASS |

### Key Insight: mxfs v2 is NOT a stacking filesystem
It reads XFS on-disk format directly — effectively a simplified XFS without journaling. This is why writes can be faster than raw XFS (no journal overhead).

### Optimizations Applied (in order)
1. **Multi-page bio** — bdev_sync_io builds 256-page bios (was 1 page per bio)
2. **Block cache readahead** — 256 contiguous blocks (1MB) on miss
3. **Direct I/O fast path** — bypass block cache when peer_count==0
4. **4MB→16MB I/O buffers** — reduce per-chunk DLM/cache overhead
5. **virt_to_page zero-copy** — no alloc/copy in bdev_sync_io
6. **Single-node alloc skip** — defer cache flush when no peers
7. **Pipelined bio reads** — 16 concurrent bios for reads
8. **kvmalloc for large buffers** — handles >4MB via vmalloc
9. **Bulk read API** — single DLM lock for entire file read
10. **Block cache rwlock yielding** — release every 256 blocks to prevent starvation
11. **cond_resched throughout** — prevent soft lockups during long I/O

### Bugs Fixed This Session (~15)
- Peer socket leak on unmount (pending_sock tracking)
- Dir cache coherency (put_dir eviction, invalidated flag, PR path check)
- DLM epoch-based stale lock detection
- DLM ghost lock purge (purge_stale_for_resource)
- DLM pending entry ordering (setup before BAST send)
- BAST for uncached inodes (cleanup unlock)
- BAST send retry (3x with backoff)
- Asymmetric multicast peer connection fallback
- Inbound peer registration with lease/DLM
- Unmount kthread shutdown (condvar + UDP shutdown)
- Lease RT priority (sched_set_fifo_low)
- Lease timing (1s renew, 60s suspect, 180s timeout, 6 misses)
- Lease send time budget (500ms cap)
- Dir cache epoch invalidation
- Unmount DLM deadlock (shutting_down before flush)
- Unconditional bdev_flush in fsync

### Network Environment
- MTU 9000 set on: clyde br0+enp6s0, ESXi vSwitch1, all 32 VMs, QNAP
- QNAP TCP MSS still 1448 despite MTU 9000 (firmware issue)
- iSCSI params capped by QNAP: FirstBurst 64KB, MaxBurst 256KB, InitialR2T=Yes
- VM→QNAP path: VM → ESXi vSwitch → clyde br0 → enp6s0 → QNAP (routed)
- clyde direct to QNAP: 101 write, 117 read MB/s
- VM to QNAP: ~65 write, ~112 read MB/s (warm cache)

## 2026-02-22 — the storage rig investigation

### Current State (as of 2026-02-22)

#### Infrastructure
- Dev machine: 192.168.120.1, NVMe local storage
- ESX hosts: esxhost1.localdomain (192.168.1.251), esxhost2.localdomain (192.168.1.252)
- Both ESX hosts are Workstation VMs at ~/vms/vmware/esxhost/ and ~/vms/vmware/esxhost2/
- vCenter: vcenter.localdomain (192.168.1.250)
- ESXi version: 8.0.2 build-22380479
- Bridge br0: 192.168.120.1, MTU 9000 (connects to ESX hosts and VMs)
- Management NIC enp6s0: 192.168.1.166, MTU 1500 (must stay 1500! ESX management network)

#### Shared Storage Setup
- iSCSI target: LIO on dev machine, block backstore + loopback with direct-io
- Image: /home/steve/iscsi-lun.img (50GB, preallocated with dd)
- Loopback: `sudo losetup --direct-io=on -f /home/steve/iscsi-lun.img` → /dev/loop0
- Target IQN: iqn.2024-01.localdomain.dev:mxfs
- Portal: 192.168.120.1:3260
- LUN NAA: naa.600140529a4fe6e7aaf45bfb09ec952c
- targetcli config saved to /etc/rtslib-fb-target/saveconfig.json
- **NOTE**: loopback --direct-io does NOT persist across reboot. Need to recreate loopback before starting target.

#### ESXi iSCSI Initiator Config
- Both hosts: vmhba65 (iscsi_vmk), software iSCSI adapter
- Discovery target: 192.168.120.1:3260 on both hosts
- esxhost1: vmk1 at 192.168.120.11/24, MTU 9000, bound to vmhba65, on vSwitch1/portgroup "iSCSI"
- esxhost2: vmk1 at 192.168.120.12/24, MTU 9000, bound to vmhba65, on vSwitch1/portgroup "iSCSI"
- SSH enabled on both hosts (TSM-SSH service)

#### RDM Setup
- VMFS datastores for RDM mapping files:
  - esxhost1: "rdm1" (2GB VMFS on local VMDK scsi0:2)
  - esxhost2: "rdm2" (2GB VMFS on local VMDK scsi0:2)
- RDM mapping files created via vmkfstools:
  - esxhost1: /vmfs/volumes/rdm1/mxfs_shared.vmdk → naa.600140529a4fe6e7aaf45bfb09ec952c
  - esxhost2: /vmfs/volumes/rdm2/mxfs_shared.vmdk → naa.600140529a4fe6e7aaf45bfb09ec952c
- All 32 test VM VMX files updated with:
  ```
  scsi0:1.present = "TRUE"
  scsi0:1.fileName = "/vmfs/volumes/rdm1/mxfs_shared.vmdk"  (odd VMs)
  scsi0:1.fileName = "/vmfs/volumes/rdm2/mxfs_shared.vmdk"  (even VMs)
  scsi0:1.deviceType = "scsi-hardDisk"
  scsi0:1.sharing = "multi-writer"
  ```
- VMs see it as /dev/sdb (50GB, model: mxfs_lun)

#### Shared Workstation VMDK (for future use)
- ~/vms/vmware/esxhost/shared.vmdk — preallocated 50GB, shared between both ESX host VMs
- Both ESX host VMX files have: scsi0:1.sharing = "multi-writer", disk.locking = "FALSE"
- Shows up as mpx.vmhba0:C0:T1:L0 on both ESX hosts (50GB, local SSD)
- Has no NAA identifier — cannot be used for RDM directly
- Could be formatted as VMFS for shared VMDK approach (not currently used)

#### Performance Benchmarks

| Configuration | Read | Write | Notes |
|---|---|---|---|
| Raw NVMe (dd on file) | 2,500 MB/s | 2,100 MB/s | Baseline |
| Raw loopback+DIO (no LIO) | 2,600 MB/s | 2,100 MB/s | Loopback adds no overhead |
| Local iSCSI loopback, block+DIO | 562 MB/s | 847 MB/s* | LIO overhead; *write suspicious |
| Guest iSCSI, fileio, MTU 1500 | 198 MB/s | 85 MB/s | Original config |
| Guest iSCSI, fileio, MTU 9000 | 198 MB/s | 158 MB/s | Jumbo frames help writes |
| Guest iSCSI, block+DIO, MTU 9000 | 260 MB/s | 195 MB/s | Best guest config |
| **ESXi RDM, vmk1 MTU 9000** | **117 MB/s** | **145 MB/s** | Current — SLOWER than guest |
| ESXi RDM, vmk0 MTU 1500 (wrong port) | 110 MB/s | 18 MB/s | Before iSCSI binding fix |

#### OPEN ISSUE: ESXi RDM iSCSI slower than guest iSCSI
- ESXi initiator (117/145) is slower than guest initiator (260/195)
- Need to investigate why — possible causes:
  - ESXi VMkernel TCP/iSCSI stack less optimized for software targets
  - RDM passthrough overhead
  - ESXi iSCSI tuning parameters (queue depth, max recv/send segments)
  - Single iSCSI session vs multiple
- **TODO**: Web search for ESXi iSCSI performance tuning, compare with guest approach

#### Bug Z Self-Deadlock Fix — IN PROGRESS
- **Root cause**: cache_get_locked() in libmxfs/inode_cache.c enters BAST wait loop when bast_pending=true.
  If the calling thread already holds a refcount (nested call, e.g. mxfs_dir_add_entry → flush_dir_immediate
  both call cache_get_locked on the same dir inode), it self-deadlocks: the wait loop needs refcount==0
  but the outer caller holds refcount==1.
- **Fix applied**: At line ~622 in inode_cache.c, added check: if bast_pending && refcount > 0, skip the
  wait loop (allow nested get). BAST completes when the outermost put() drops refcount to 0.
  Added debug log for this path. The existing timeout/eviction logic is now inside an else block for
  the refcount==0 case only.
- **Build status**: Compiled clean on 6.8 kernel (dev machine). NOT YET built on 6.1 (test nodes).
- **Test status**: NOT YET TESTED. Previous attempt (before this fix) deadlocked on 4-node concurrent
  file creation. Need to: build on test1, deploy to all 4 nodes, run concurrent touch test.
- **Reproducer**: On each of 4 nodes simultaneously: `for i in $(seq 1 50); do touch /mnt/shared/testN_file_$i; done`
- XFS needs to be reformatted on /dev/sdb before MXFS testing

#### SCSI-3 PR Testing via RDM
- RDM setup passes SCSI commands directly to the iSCSI LUN — should support SCSI-3 PR
- This has NOT been tested yet with the RDM path
- Guest iSCSI approach has been working with SCSI-3 PR all along
- Worth testing: does MXFS SCSI-3 PR (register/reserve/preempt) work through the ESXi RDM path?
- If RDM PR works, we could use RDM for PR fencing + guest iSCSI for data I/O (but that's complex)
- Simplest approach: just use guest iSCSI for everything (faster, proven to work with PR)

#### Current VM State (end of session)
- test1-test4: POWERED ON, RDM attached, /dev/sdb visible (50GB mxfs_lun)
- test5-test32: powered off, VMX files updated with RDM entries
- ESX hosts: both up, iSCSI initiators configured with vmk1 on 192.168.120.x MTU 9000
- iSCSI target: running on dev machine (block backstore, /dev/loop0, DIO)
- /dev/sdb has raw data from benchmark dd — needs `mkfs.xfs -f /dev/sdb` before MXFS use
- mxfs.ko: built on dev machine (6.8), NOT yet built on test nodes (6.1)
- NFS probably not mounted on test nodes (they were freshly booted)

#### Startup Checklist for Next Session
1. Symlink password file: `ln -s ~/.mxfs/pass /tmp/.mxfs_pass`
2. Verify loopback+iSCSI target running: `sudo targetcli ls /`
   - If not: `sudo losetup --direct-io=on -f /home/steve/iscsi-lun.img && sudo systemctl restart rtslib-fb-targetctl`
3. Verify br0 MTU: `ip link show br0` — should be 9000
4. Keep enp6s0 at MTU 1500! (management network)
5. Power on ESX hosts, verify "connected" in vCenter
6. Power on test VMs, verify /dev/sdb visible
7. Set MTU 9000 on test VMs: `sudo ip link set eth0 mtu 9000` (doesn't persist)
8. Mount NFS on test nodes: `sudo mount -t nfs 192.168.120.1:/home/steve/src/mxfs /mnt/mxfs-src`
9. Build on test1: `cd /mnt/mxfs-src/v2 && make clean && make`
10. Format XFS: `sudo mkfs.xfs -f /dev/sdb` (on one node only, others not connected)
11. Deploy and test Bug Z fix (4-node concurrent file creation)

#### Decision Needed Next Session
- **Storage approach**: Guest iSCSI (faster, 260/195 MB/s, proven) vs ESXi RDM (117/145 MB/s, needs PR test)
- Could keep RDM config in VMX files and also use guest iSCSI — just don't mount both simultaneously
- Recommend: test SCSI-3 PR through RDM once, then decide. If guest iSCSI PR still works (it should),
  switch back to guest iSCSI for all testing since it's 2x faster.

## 2026-03-06 — mkfs.mxfs

### Status: DONE (Session 13, 2026-03-06)

### Disk Layout
```
|<-- XFS data -->|<-- journal ~64MB -->|<-- disklock ~32MB -->|<-- super 4KB -->|
0                journal_offset        disklock_offset        super_offset  dev_end
```

### Region Sizes
- Journal: 512B super + 64 x 1MB slots = 67,109,376 bytes
- Disklock: 32KB heartbeat + 32MB locks = 33,587,200 bytes
- MXFS super: 4,096 bytes
- Total reserved: 100,700,672 bytes (~96MB)

### On-Disk MXFS Super (last 4KB of device)
- Magic: 0x4D585346 ("MXSF") — distinct from VFS MXFS_SUPER_MAGIC (0x4D584653)
- Struct: `mxfs_ondisk_super` in `include/mxfs/mxfs_super.h`
- Fields: magic, version, crc, fs_uuid, device_size, xfs_data_size, journal_offset, journal_size, disklock_offset, disklock_size, max_nodes, journal_slot_sectors
- CRC32C with crc field zeroed

### Files Created
- `include/mxfs/mxfs_super.h` — shared on-disk super struct
- `tools/mkfs_mxfs.c` — standalone format tool (~400 lines, no libmxfs linkage)
- `tools/Makefile` — `gcc -Wall -O2 -I../include -o mkfs.mxfs mkfs_mxfs.c`
- `tools/mkfs_mxfs.md` — documentation

### Files Modified
- `pal/pal.h` — added mxfs_pal_bdev_size()
- `pal/pal_linux_kern.c` — bdev_nr_bytes() with 5.16 compat fallback
- `pal/pal_linux_user.c` — BLKGETSIZE64 ioctl + stat fallback, added sys/stat.h + linux/fs.h
- `libmxfs/mount.h` — added mxfs_super.h include
- `libmxfs/mount.c` — auto-detect after bdev_open, changed opts-> to mnt->opts. for offset refs
- `include/mxfs/mxfs_common.h` — version 1.2.0 → 1.3.0

### Key Design Decisions
- Standalone tool (no libmxfs link) — inline CRC32C table, duplicate journal constants
- On-disk super at END of device (last 4KB) — won't conflict with XFS at start
- Auto-detect in mount.c: read last 4KB, validate magic+CRC, populate offsets
- All offset references changed from opts-> to mnt->opts. so auto-detected values propagate

### Test Results
- Single-node (test1): PASS — format, mount without offsets, touch, persistence
- Four-node (test1-4): 4/4 PASS — auto-detected, cross-node visibility
- Builds clean on 6.8 (dev) and 6.1 (test nodes)

## 2026-03-10 — the production-readiness roadmap (session-34 audit)

Created: 2026-03-10 (Session 34 audit)
Updated: 2026-03-10 (Session 34 — all items complete except final pre-release)
Target: Proxmox team evaluation submission

### Status: ALL IMPLEMENTATION COMPLETE

Everything from Tier 1, 2, and 3 was implemented in Session 34.

#### Completed (Session 34)
1. Bug 109: B+tree extent write + multi-level (v1.8.0 → v1.8.1)
2. Bug 115: mknod — device nodes, FIFOs, sockets (v1.8.2)
3. Bug 116: Long symlinks — FMT_EXTENTS read/write (v1.8.3)
4. Bug 110: xattrs — user/trusted/security namespaces, shortform
5. Bug 111: POSIX ACLs — get/set/inherit, SB_POSIXACL
6. Bug 114: POSIX file locks — fcntl/flock, local-node semantics
7. Bug 113: fallocate — prealloc + KEEP_SIZE + PUNCH_HOLE
8. Bug 112: mmap — page_mkwrite with DLM EX lock
9. SEEK_HOLE/SEEK_DATA — extent map walk
10. Mount options — noatime/relatime/nodiratime/strictatime
11. Splice I/O — filemap_splice_read + iter_file_splice_write
12. Rename flags — RENAME_NOREPLACE + RENAME_EXCHANGE
13. Freeze/thaw — sync + journal checkpoint
14. FINOBT in mkfs — finobt root per AG, resize_mxfs updated
15. Log cleanup — 67 chatty INFO → DEBUG
16. Man pages — mkfs.mxfs.8, chk_mxfs.8, resize_mxfs.8, mxfs.5
17. chk_mxfs improvements — BNO/CNT/inobt/finobt btree walk, inode spot-check, cross-checks

#### Remaining — pre-release only
18. Version renumbering: relabel history as 0.x alpha/beta, stamp 1.0.0 on release
19. Final test pass on Proxmox cluster (VM create, VM failover, multi-node stress)

### Post-v1.0.0 (future)
- Quotas (very large)
- Online resize (large)
- Cluster-aware POSIX file locks (large)
- FreeBSD port (large)
- GitHub Actions CI (medium)
- Leaf/node xattr format for large attrs (medium)

## 2026-03-22 — the architecture decision that produced v5

At v0.3.2 in `mxfs.new`, with v0.14.0 in `~/src/mxfs` already abandoned. This is
the assessment that ended the hand-written-filesystem line and chose the kernel
XFS fork.

### 1. What Happened

#### Original Vision
Build a multi-platform clustered filesystem (Linux, macOS, FreeBSD) that uses the
XFS v5 on-disk format. Multiple nodes share a single block device with full read/write
access. Single deliverable: mxfs.ko kernel module (Linux), with future ports.

#### What We Actually Built (twice)

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

#### The Core Mistake

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

### 2. Benchmark Evidence

#### XFS Baseline (test1 VM, Samsung 870 1.8TB, tcm_loop/CAW, 2026-03-22)

| Test | BW (MB/s) | IOPS |
|------|-----------|------|
| Seq Write 1M | 509.2 | 509 |
| Seq Read 1M | 540.3 | 540 |
| Rand Write 4K | 253.6 | 64,921 |
| Rand Read 4K | 323.9 | 82,928 |

#### MXFS v0.3.2 (same setup, same day)

| Test | BW (MB/s) | IOPS | Overhead vs XFS |
|------|-----------|------|----------------|
| Seq Write 1M | 11.4 | 11 | 44.8x |
| Seq Read 1M | 39.9 | 40 | 13.5x |
| Rand Write 4K | 6.6 | 1,683 | 38.6x |
| Rand Read 4K | 6.3 | 1,619 | 51.2x |

#### Old MXFS v0.9.27 on same hardware (bench.json, session 65)

| Test | BW (MB/s) | IOPS | Overhead vs XFS |
|------|-----------|------|----------------|
| Seq Write 1M | 226.3 | 226 | 2.3x |
| Seq Read 1M | 347.4 | 347 | 1.6x |
| Rand Write 4K | 8.1 | 2,069 | 24.7x |
| Rand Read 4K | 10.8 | 2,759 | 29.1x |

### 3. Kernel XFS Architecture (~/src/linux/fs/xfs/)

245 files, 169K lines total. Two layers:

#### libxfs/ (80K lines) — Portable metadata logic
- B-tree engine (alloc, bmap, ialloc, refcount, rmap)
- On-disk format definitions and CRC verification
- AG management, inode fork operations
- Directory operations (sf, block, leaf, node)
- **This is shared between kernel and xfsprogs** — it's format logic only

#### Top-level fs/xfs/ (89K lines) — Linux kernel integration
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

#### Kernel API Dependencies
- iomap: 111 references (core to read/write path)
- spin_lock: 173 references
- folio: 48 references (modern page abstraction)
- mutex_lock: 32 references
- kmem_cache: 22 references (slab allocator)
- submit_bio: 11 references (surprisingly few — most I/O through iomap/xfs_buf)
- workqueue/queue_work: 18 references
- 6 dedicated workqueues at mount time

### 4. Architecture Options for Next Project

#### Option A: Linux-Only Kernel Module (Fork Kernel XFS)

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

#### Option B: Multi-Platform with Kernel XFS I/O Engine (PAL Abstraction)

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

#### Option C: Linux-Only, Loadable Kernel Module (Recommended)

Same as Option A but designed as a loadable module (not requiring kernel rebuild).
Fork fs/xfs/ into mxfs, build as out-of-tree module. Use DKMS for deployment.

**Additional considerations:**
- Can use GPL-exported kernel symbols (iomap, bio, page cache APIs)
- Module can register its own filesystem type ("mxfs")
- Both XFS and MXFS can coexist (different fs type names)
- Users format with `mkfs.mxfs` which writes the MXFS super + journal + disklock
  regions before the XFS data area (same as current layout)

### 5. What to Preserve from Prior Projects

#### From ~/src/mxfs (v0.14.0) — see handoff.md
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

#### From /src/mxfs.new (v0.3.2) — this project
- mkfs_mxfs — format tool with MXFS super + journal + disklock + XFS data layout
- chk_mxfs — filesystem checker
- resize_mxfs — online resize
- On-disk layout (4KB MXFS super, 64MB journal, 32MB disklock, XFS data)
- DLM (refined from old project)
- Cluster coordination (refined from old project)
- Test infrastructure (updated)
- VM setup runbooks (docs/qemu_direct_caw.md, docs/qemu_tcm_loop_setup.md)
- Deployment scripts (scripts/, tools/prep_tcm_node.sh, tools/mxfs_deploy.sh)

#### Test Infrastructure (shared)
- 32 VMs: test1-test32, Ubuntu 24.04, 2 vCPU / 2GB, bridged to br0
- Host: clyde (192.168.1.166 / 192.168.120.1)
- Shared storage: Samsung 870 1.8TB via tcm_loop/iblock + QEMU scsi-block
- Credentials: root / <REDACTED-ROTATED>, password file /tmp/.mxfs_pass
- NFS: 192.168.1.4:/src mounted at /src in guests
- Physical servers: pve1 (192.168.1.80), pve2 (192.168.1.81) — Proxmox, iSCSI to QNAP

### 6. Key Architectural Invariants (Carry Forward)

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

### 7. Recommended Next Steps

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

### 8. Reference Files

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

## 2026-05-07 — mxfs.1 measured against v5 on the same hardware

### ⚠️ UPDATE 2026-05-07 (post-rsync-bench, supersedes morning headline)

The morning's "mxfs.1 is in better correctness shape than v5" headline
was based on dd / fio / metadata-storm only.  An rsync-bench run later
the same day exposed a single-node correctness bug that the morning
sweep missed.

**Single-node corruption on rsync of element-web** (4,385 files /
971 dirs, JS-app deep nesting):
  - Bug location: `libmxfs/dir_cache.c::flush_*_dir` — dir format
    transition (likely SF→block→leaf) corrupts dir blocks during
    writeback.
  - Symptom: dmesg fills with `dir_cache: block dir ino N:
    unexpected magic 0xNNNNNNNN, attempting parse anyway`.  The
    recovery branch produces binary-junk filenames and bogus inode
    numbers (in the trillions).
  - User-visible: rsync silently drops ~84% of the tree, exits 23.

**Single-node perf degradation on rsync of open-gpu** (no corruption
triggered, but journal saturates faster than it drains):
  - Iter 1: 13s, Iter 2: 88s, Iter 3: 116s.

**XFS native baseline on same hardware:** 2.5-3.7s on both trees,
full md5 integrity.

**Implication for v5 vs mxfs.1 decision:**
  - mxfs.1's morning numbers (1.00x XFS fio, 100% pass on 2-node dd
    stress) are real for those workloads, but they do NOT generalize
    to realistic create-heavy nested workloads.
  - mxfs.1 has a SINGLE-NODE corruption bug that v5 does not have.
    v5's bugs are cross-node.  Different bug surface, not strictly
    "mxfs.1 better."
  - Neither version is currently production-ready on this hardware.
    The decision is harder, not easier.

### Original sess74 morning section (kept for context — note caveat above)

mxfs.1 (the first-attempt MXFS at `~/src/mxfs.1/`) was resurrected and
validated in session 74 on 2026-05-07, on the same hardware that v5 is
tested on (test1 + test2 on clyde, kernel 6.8.0-101, Samsung 870 EVO
via tcm_loop+iblock CAW).

### Headline numbers (use these when comparing v5 to mxfs.1)

| Workload | mxfs.1 v0.14.0 | v5 sess30 (v0.3.128) |
|---|---|---|
| fio seq write 1m single-node | 505 MiB/s = 1.00x XFS | ~99% XFS |
| fio rand write 4k single-node | 261 MiB/s = 1.03x XFS | ~91-96% XFS |
| 5×256 cross-node × 5 samples | 25/25 = 100% | 20/25 = 80% |
| 15×256 × 3 samples | 45/45 = 100% | mixed: 4/15, 1/15, 15/15 |
| 15×512 × 3 samples | 45/45 = 100% | mixed: 6/15, 8/15, 7/15 |
| Metadata stress 10 min | PASS, no corruption | not measured |

### Where the data actually lives

- `/home/steve/src/mxfs.1/state.md` — sess74 section at top, dated 2026-05-07.
- `/home/steve/src/mxfs.1/bench.json` — `sess74_resurrect_v0140_fio`
  entry (canonical fio sweep), `sess74_resurrect_v0140_dd` (paired
  XFS / mxfs.1 dd numbers).
- `~/.claude/projects/-src-mxfs-1/memory/sess74_lessons.md` —
  **project-scoped to mxfs.1, will NOT auto-load in /src/mxfs sessions.**
  If working on cross-version comparisons, read it explicitly.

### Real open issues in mxfs.1 (not a free win)

1. CAW disk-lock table is hard-capped at 4096 entries
   (`libmxfs/disklock.c`). Saturates at OS-install scale (~10K-100K
   files). Produces 120s timeouts. Needs dynamic sizing or aggressive
   LRU eviction before mxfs.1 is production-grade for full-tree workloads.

2. Cross-node visibility window without writer-sync — test2 writes,
   test1 reads without intervening sync, sees `init_special_inode:
   bogus i_mode (0)`. Same "Mode A" class as v5 has been chasing.
   Workaround: writer fsync. Real fix: BAST flush dirty inodes before
   granting.

3. Allocator self-heal dmesg events (`cntbt/bnobt desync`, `chunk
   not found in inobt`, `stale sb`) — appear during normal operation,
   self-correct, KERN_NOTICE level. Same bug family v5 has been
   chasing reactively; mxfs.1 reconciles silently.

### How to apply

- **Don't claim v5's perf advantage over mxfs.1 without re-measuring
  on the same hardware in the same session.** Sess30 was implicitly
  comparing v5 (99% XFS measured) against mxfs.1's stale v0.13.0
  rsync number (24% XFS) — the freshly-measured fio numbers in
  sess74 invalidate that framing.
- **Don't assume v5's manual-bio CAW fix is needed for mxfs.1.**
  Sess74 confirmed mxfs.1's PAL also calls scsi_execute_cmd and
  passes 100% at 2-node. The bio-aliasing hypothesis behind v5's
  fix doesn't appear to bite mxfs.1 at 2 nodes. Don't port v5's
  fix to mxfs.1 prophylactically.
- **Storage-side facts (FUA-on-write semantics, Samsung 870 EVO
  bdev_fua=0, LIO emulate_write_cache=0) are real and apply to BOTH
  v5 and mxfs.1.** Sess30 documented these for v5; sess74 reconfirmed
  them for mxfs.1. They are environmental, not version-specific.

## Bug-fix history before v5

### Bugs 1-28 (chronological)
1. **BAST cache invalidation** — membership_cb drops all caches on peer discovery (dlm.h/c, mount.c, inode_cache.h/c, dir_cache.h/c)
2. **Peer recv thread shutdown** — two-phase: kernel_sock_shutdown before close (pal.h, pal_linux_kern.c, pal_linux_user.c, peer.c)
3. **DLM lock timeout on unmount** — flush caches before NODE_LEAVE, shutting_down flag (dlm.h/c, mount.c)
4. **Extent serialization** — flush_inode_to_disk now serializes extent map to raw buffer (extent.c/h, inode_cache.c)
5. **nextents not updated** — ci->nextents never incremented during writes, flushed as 0 (mount.c)
6. **format field not serialized** — flush_inode_to_disk didn't write ci->format to raw buffer (inode_cache.c)
7. **VFS inode size stale** — mxfs_read_iter used cached i_size without refresh (frontend/linux/file.c)
8. **SCP deploy bug** — scp -r creates nested dirs when dest exists; must rm old + SCP to parent
9. **Node 203/204 insmod** — needs `modprobe libcrc32c` before insmod (crc32c symbol missing)
10. **Dir shortform-to-block upgrade** — flush_block_dir() in dir_cache.c converts SF to XFS block format when entries exceed inline limit (dir_cache.c/h, alloc wired in via set_alloc)
11. **AG affinity from node_id** — node_slot auto-derived from node_id in mount.c when not explicitly set (mount.c)
12. **Dir cache BAST flush for block dirs** — flush_block_dir() called in BAST path for FMT_EXTENTS dirs (dir_cache.c) [Bug G fix]
13. **Peer TCP reconnection** — discovery only fired peer_cb for new peers; after ECONNRESET no reconnect. Fixed: fire for all announcements + join old recv_thread (discovery.c, peer.c)
14. **DLM active node double-counting** — local node added twice to active list (manually + from lease). Fixed: removed manual addition (mount.c)
15. **Inode flush R-M-W race (Bug M)** — flush_inode_to_disk did 4K block R-M-W, nodes clobbered each other's inodes. Fixed: per-inode 512-byte direct write (inode_cache.c)
16. **Dead nodes in DLM active list (Bug N)** — peer disconnect didn't update active_nodes. Fixed: remove_node() helper in mount.c
17. **DLM active node dedup (Bug O)** — dedup after sort in dlm.c update_active_nodes
18. **Dir cache BAST refcount wait** — BAST handler raced with active dir modifications. Fixed: refcount wait loop in dir_cache.c
19. **Eager dir flush (Bug R)** — flush dir to disk immediately after modification, BAST handler just discards cache (dir_cache.c)
20. **Bug S — leaf-format dir detection** — load_dir_from_disk() used size heuristic, failed for 1-data-block leaf dirs. Fixed: check for leaf extent at XFS_DIR2_LEAF_OFFSET.
21. **readdir cache invalidation** — get_dir_mode() PR path never checked lock_gen. Fixed: added lock_gen mismatch check + block cache invalidation in PR path.
22. **Leaf-format extent growth** — flush_leaf_dir() assumed existing data extent large enough for num_data_blocks. Fixed: detect undersized extent, free+realloc larger.
23. **Debug logging in code** — ino 128 specific logging in inode_cache.c and dir_cache.c, remove after fixes confirmed
24. **DLM FIFO grant ordering (Bug T)** — promote_waiters granted in LIFO order (newest waiter first), causing starvation at 32 nodes. Fixed: added `queued_at` to struct mxfs_lock, sort by queued_at. (dlm.h, dlm.c)
25. **DLM batch limit hang (Bug U)** — fixed-size batch arrays silently dropped BASTs/grants beyond 16. Fixed: eliminated ALL batch arrays, replaced with embedded linked lists via `work_next`. (dlm.h, dlm.c)
26. **Bug X — rmdir on non-empty dirs** — nlink > 2 heuristic only caught subdirs. Replaced with actual dir entry scan via rmdir_count_cb() callback (mount.c)
27. **Bug Y — stale dir entries after bulk unlink** — flush_leaf_dir() never shrank extent map. Fixed: parser ci->size limit + extent shrink + block cache invalidation (dir_cache.c)
28. **Bug Z — inode cache self-deadlock** — cache_get_locked() in inode_cache.c enters BAST wait loop when bast_pending=true. If calling thread already holds refcount (nested call, e.g. dir_add_entry → flush_dir_immediate both call cache_get_locked on same dir inode), it self-deadlocks: wait loop needs refcount==0 but outer caller holds refcount==1. Fixed: skip BAST wait loop when refcount > 0 (nested get allowed, BAST completes when outermost put() drops to 0). Built clean on 6.8 — NOT yet built on 6.1 or tested on cluster. Reproducer: 4-node concurrent `touch` (50 files each).

### Bugs 29-41
(Documented in session logs; includes journal replay fixes, 4-node regression fixes, DLM transport flapping (Bug 41), and various multi-node stability improvements.)

### Bugs 42-43 + Architecture Changes (2026-02-20, Phase 5 Scale Testing)

42. **Inode/dir/block cache UAF in drop_all** — pinned entries freed while writers hold references. All three caches (inode_cache.c, dir_cache.c, block_cache.c) skip pinned entries during drop_all; pinned entries marked invalid for deferred cleanup when writer releases.

43. **Peer socket UAF in recv_fn** — socket freed (tcp_close) while recv thread blocking in sk_wait_data. Fixed: shutdown-before-close pattern in 3 locations: accept thread replacement, peer_connect_impl, peer_send failure. (peer.c) Verified: zero crashes across 16 nodes.

#### Architecture Change: UDP Lease Renewals
- **Not a bug fix** — scaling improvement to eliminate TCP congestion at 16+ nodes
- Files: libmxfs/lease.c, libmxfs/lease.h, libmxfs/mount.c, pal/pal.h, pal/pal_linux_kern.c, pal/pal_linux_user.c
- Replaced per-peer TCP unicast lease renewals with single UDP multicast send on port 7602 (separate from discovery 7601)
- Added wire format with mxfs_cpu_to_le64/mxfs_le64_to_cpu PAL helpers
- Eliminates N TCP sends per renewal interval; critical for 16+ node clusters where TCP congestion was blocking lease renewals and causing false DEAD declarations

### Bugs 44-48 (2026-02-22, 4-Node Concurrent Metadata Stress)

44. **Dir entry loss race during concurrent multi-node creation** — multiple nodes adding entries to the same directory concurrently could lose entries due to BAST invalidation between read-modify-write. Fixed with lock_gen check in dir_cache.c (Bug 44).

45. **DLM lock timeout causes file loss under heavy contention** — 30s DLM timeout too short for 4-node concurrent directory writes. Increased to 120s. Retry-with-backoff approach reverted after causing duplicate entries and D-state deadlocks (Bug 45, take 2).

46. **Duplicate dir entries during membership change** — membership flap (4→3→4 nodes) during concurrent creates produces duplicate directory entries. Membership callback drops all caches, and in-flight add_entry operations may re-add entries already flushed to disk. (OPEN — low priority until happy-path testing is clean)

47. **Lease renewal starvation under heavy metadata I/O** — UDP recv thread was normal CFS priority while renew/monitor were RT. Under heavy I/O, recv thread starved for 60+ seconds, heartbeats unprocessed. Fixed: upgraded UDP recv thread to RT priority (all 3 lease threads now SCHED_FIFO low). Also increased SUSPECT_MISSES from 6 to 60 (180s before SUSPECT). (lease.c, lease.h)

48. **Inode cache UAF during epoch mismatch eviction** — epoch mismatch handler evicted and freed cached inodes without checking refcount. If another thread held a reference (pinned), the freed memory corrupted nextents to garbage (e.g., 1385570172), causing -ENOSPC from extent serialization. Fixed: if refcount > 0, release stale DLM lock and re-acquire at current epoch in-place, reload from disk. Only evict+free when refcount == 0. (inode_cache.c)

### Bugs 49-57 (2026-02-25/26, Dir Cache Coherency Deep Dive)

49/49b. **Dir cache stale data on lock upgrade** — inode reload on NL→EX didn't cover PR→EX. Dir cache lock_gen check only on miss, not hit. Fixed: reload inode on ANY lock upgrade (Bug 50e); lock_gen check on cache hit regardless of refcount (Bug 50g). (inode_cache.c, dir_cache.c)

50. **Flush-before-drop in membership callback** — dirty caches dropped without flushing during membership change. Multiple sub-fixes (50b-50g) explored; ultimately dir entries are eagerly flushed so the correct action is DISCARD during membership change, not flush. (mount.c, dir_cache.c, inode_cache.c)

51. **DLM dual-EX prevention (send-ordering race)** — LOCK_REQ arriving before LOCK_RELEASE caused "already granted" shortcut to grant EX while another node still held EX. Fixed: state-based detection in handle_lock_request checks for conflicting WAITING/BLOCKED entries from other nodes. (dlm.c)

52. **Direct bdev reads for directory blocks** — block cache held stale dir data blocks across lock bounces. Fixed: bypass block cache for all dir data reads, read directly from bdev. (dir_cache.c)

53. **Node-format dir writeback** — leaf dir overflow at ~502 hash entries truncated instead of growing. Fixed: proper XFS node-format writeback for directories exceeding leaf capacity. (dir_cache.c)

54. **Phantom cached EX lock (pending BAST race)** — DLM promote_waiters grants local lock, but before dlm_lock() returns and creates cache entry, another BAST arrives. bast_cb finds NOT_IN_CACHE, releases the legitimately granted lock as "residual". Node then operates with phantom EX (cached but no DLM backing). Fixed: record pending_bast_ino instead of releasing; cache_get_locked applies deferred BAST after creating the entry. (inode_cache.c, inode_cache.h) **ROOT CAUSE of persistent dual-EX.**

55. **Slab heap corruption from leaked extents/inline_data** — load_inode_from_disk() called on existing ci during lock-upgrade reload overwrote ci->extents and ci->inline_data without freeing old allocations. Leaked objects corrupted SLUB freelist. Fixed: free old allocations at top of load_inode_from_disk(). (inode_cache.c)

56. **complete_bast UAF from concurrent access** — Three sub-fixes: (a) pin ci during epoch-mismatch flush, (b) skip lock upgrade if bast_pending to avoid concurrent ci->extents access, (c) check refcount after complete_bast flush — if another thread acquired reference during I/O window, defer removal. (inode_cache.c)

57. **Remote BAST recv thread deadlock** — remote BAST message processed inline on peer recv thread called complete_bast which acquired cache->rwlock. Concurrent touch thread held rwlock waiting for DLM grant message — which arrived on the same blocked recv thread. Fixed: route remote BASTs through bast_worker_fn thread (same as local BASTs). (mount.c)

58. **Duplicate dir entries during membership change (Bug 46 root cause)** — Two-part fix: (a) Epoch mismatch handler for pinned inodes re-acquired the DLM lock at `requested_mode` (from the current caller) instead of the existing `ci->lock_mode`. When `flush_dir_immediate` (PR caller) triggered epoch mismatch on an inode held at EX by `get_dir_exclusive`, the handler silently downgraded EX→PR, breaking exclusive access. Fix: re-acquire at MAX(existing, requested) mode. (inode_cache.c) (b) `flush_dir_immediate` flushed invalidated dir cache entries (stale subset of directory) to disk, overwriting the complete on-disk directory with partial data. Fix: check `cd->invalidated` at top of flush and return -EAGAIN; existing retry logic in add/remove/rename_entry drops stale cache and reloads from disk. Also added epoch checks in flush_dir_immediate, flush_leaf_dir, flush_block_dir, and flush_shortform_dir — if DLM epoch changes during inode_cache_get[_exclusive] (from epoch mismatch handler), abort flush and return -EAGAIN. (dir_cache.c) Validated: 0 duplicates with intentional node kills. BUT: happy-path 4-node 2500/node still produces duplicates — epoch fix is necessary but not sufficient.

59. **Stale dir data blocks read beyond ci->size boundary** — flush_leaf_dir may write N data blocks but the underlying extent may be larger (allocated for a previous flush with more entries). parse_leaf_or_node_dir read ALL blocks in the extent, picking up stale entries from blocks beyond the valid range. Fix: limit data block reads to `ci->size / dir_blksize` in parse_leaf_or_node_dir. (dir_cache.c) Verified: read limiter works correctly (69/69 blocks read for 10000 entries). BUT: 2298 duplicates still appear during happy-path 4-node — the duplicates are being WRITTEN to disk, not just read from stale blocks. Root cause still open.

### Bug 93 (2026-03-05, Session 10)

93. **Module refcount leak on unmount** — `mxfs_kern_kill_sb` used `generic_shutdown_super(sb)` but the filesystem was mounted via `mount_nodev()` which allocates an anonymous bdev via `set_anon_super`. The matching cleanup is `kill_anon_super()` which calls both `generic_shutdown_super()` AND `free_anon_bdev()`. Without the anon bdev cleanup, the VFS module refcount tracking left refcnt=1 after unmount, blocking rmmod. Fix: replaced `generic_shutdown_super(sb)` with `kill_anon_super(sb)` in `mxfs_kern_kill_sb`. (frontend/linux/mxfs_super.c) Verified: 2 full mount/unmount/rmmod cycles, refcount correctly drops to 0.

### Bug 103 (2026-03-09, Session 29)

103. **VFS dentry type staleness on cross-node inode number reuse** — When node A deletes a regular file and creates a directory reusing the same inode number, nodes B/C get ENOTDIR when traversing the directory (e.g., `ls dir/`, `cd dir/`). `stat` shows correct directory type. Root cause: `iget_locked` returns cached VFS inode with old S_IFREG mode. `mxfs_kern_fill_inode` updates `i_mode` to S_IFDIR and sets dir ops. But `d_splice_alias` finds existing dentry alias of the old inode with stale `DCACHE_REGULAR_TYPE` flags. `d_move` does NOT update dentry type flags. Result: dentry with DCACHE_REGULAR_TYPE pointing to S_IFDIR inode → ENOTDIR on path traversal. Fix: In `mxfs_kern_iget`, get on-disk state via `mxfs_stat` BEFORE `iget_locked`. For existing (non-I_NEW) inodes with type change, call `d_prune_aliases(inode)` + `remove_inode_hash(inode)` + `iput(inode)` to evict the stale VFS inode, then retry `iget_locked` to get a fresh I_NEW inode with correct type. Workaround: `echo 2 > /proc/sys/vm/drop_caches` clears stale dentries. (frontend/linux/mxfs_super.c) Verified: 3-node physical test — file→directory with same name works correctly across all nodes.

### Bug 104 (2026-03-10, Session 30)

104. **DLM transport auto-detection + SCSI PR reservation conflict on TCP DLM** — Two related problems: (a) Joining a TCP DLM cluster with default CAW transport caused 30s DLM lock timeout on root inode because QNAP doesn't support SCSI Compare-And-Write. (b) SCSI PR registration on QNAP NAS caused reservation conflicts (-52 EBADE) that blocked ALL disk I/O (heartbeat writes, dir cache flushes, inode flushes) from other nodes, crashing the entire cluster. Root cause: QNAP's SCSI PR type 5 (WRITE EXCLUSIVE - REGISTRANTS ONLY) implementation is broken — it rejects writes from registered initiators that aren't the reservation holder. Fix: (1) Added `MXFS_DLM_TRANSPORT_AUTO` as new default. On mount, listens for peer discovery announces for 3s. If peers found, adopts their `dlm_transport` field from the announce packet. If no peers, probes device with a SCSI CAW operation — success/MISCOMPARE means device supports CAW, any other error falls back to TCP. (2) Skip SCSI PR entirely for TCP DLM — TCP uses network-based fencing (connections + leases), not hardware fencing. (3) Added `dlm_transport` field to discovery announce packet (replaces 1 byte of pad, wire-compatible). Files changed: mxfs.h, mxfs_common.h, discovery.h/c, mount.c, mxfs_super.c. Verified: 2-node cluster (clyde kernel 6.8 + z440 kernel 5.10) auto-detects TCP, cross-node read/write PASS, 100 concurrent metadata ops PASS, zero heartbeat failures.

### Bug 129 (2026-03-12, Session 53)

129. **Negative df / free_blocks counter drift** — `df` showed -1064% usage on pve2. Root cause: the allocator initialized `ctx->free_blocks` from the XFS superblock `sb->fdblocks`, but the superblock was never written back on sync/unmount. After remount, the stale fdblocks caused the live counter to diverge from the AGF ground truth. Freeing blocks allocated in a prior mount session incremented the counter past `dblocks`. Observed: sb fdblocks=13,075,974, AGF sum=13,077,295, in-memory=13,351,803 (drift=+274,508). Fix (3 parts): (1) `mxfs_alloc_create()` sums `agf_freeblks` across all AGs as initial `free_blocks` instead of trusting stale `sb->fdblocks`. (2) `mxfs_free_blocks()` caps `ctx->free_blocks` at `sb->dblocks` with warning log. (3) New `flush_superblock_counters()` writes fdblocks/icount/ifree back to XFS superblock (with V5 CRC) during `sync_fs`. Files changed: alloc.c, mount.c, mxfs_common.h, VERSION. Verified: pve2 mount shows correct 1% used, on-disk fdblocks matches AGF truth after sync.

### Bug 133 (2026-03-13, Session 57, FIXED in v0.9.23)

133. **Superblock flush clobbers AG 0 headers** — `flush_superblock_counters()` wrote the full 4K block 0 via `mxfs_block_cache_write()`, clobbering AGF (sector 1) and AGI (sector 2) of AG 0. Fix: Use `mxfs_block_cache_write_range()` to write only the SB sector (offset 0, 512 bytes). Files changed: mount.c.

### Bug 134 (2026-03-13, Session 57, FIXED in v0.9.24)

134. **df divergence across cluster nodes** — 4-node cluster showed different df values on each node (clyde 634M, serv 798M, pve1 3.3G, pve2 1.2G used). Root cause: `ctx->free_blocks` is a per-node in-memory counter initialized from AGF sum at mount time, only updated by LOCAL alloc/free operations. Other nodes' allocations update AGF on disk (under DLM AG lock) but no mechanism existed to propagate changes to other nodes' in-memory counters. Also, `flush_superblock_counters()` wrote the LOCAL stale counter to the on-disk superblock on sync — last node to sync wins, corrupting the SB. Fix: New `mxfs_alloc_recount_counters()` reads AGF.freeblks, AGI.count, AGI.freecount directly from disk (bypassing stale block cache), flushes cached AG dirty blocks first. Called by `mxfs_statfs()` and `flush_superblock_counters()`. `MXFS_LTYPE_SUPER` was dead code (defined in enum but never used). Files changed: alloc.c, alloc.h, mount.c, mxfs_common.h, VERSION.

### Bug 132 (2026-03-13, Session 58, FIXED in v0.9.25)

135. **Double block allocation on DLM membership change race** — Guard map detected agbno 1061 in AG 43 being allocated repeatedly on pve1, and agbno 126158 in AG 18 on clyde. No data corruption observed (sha256 matches) but the allocator was handing out the same blocks twice. Root cause: `mxfs_dlm_update_active_nodes()` purges the entire DLM lock table synchronously (all lock entries destroyed), then `dlm_membership_cb()` signals the cache flush worker thread asynchronously. Between the synchronous purge and the async `mxfs_alloc_release_cached_ag()`, `lock_ag()` gets a false cache hit on the stale `cached_ag` field (DLM lock entry is gone but `cached_ag >= 0`). Meanwhile another node retries its pending lock request and gets immediate EX grant from the now-empty lock table. Both nodes hold "EX" on the same AG and modify bnobt/cntbt simultaneously. Fix: `lock_ag()` now stores the DLM epoch in `cached_ag_epoch` when caching an AG lock. On cache hit, verifies `mxfs_dlm_get_epoch(ctx->dlm) == ctx->cached_ag_epoch`. Epoch advances on every membership change, so a mismatch means the lock table was purged — flush dirty blocks and re-acquire from DLM. Cannot call `mxfs_alloc_release_cached_ag()` synchronously from the DLM callback because lock ordering (alloc->lock → dlm->mutex in normal path) would deadlock. Files changed: alloc.h, alloc.c, VERSION.
