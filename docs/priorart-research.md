# MXFS prior-art research dossier

**Started:** sess28 (2026-05-06)
**Sources read:** `~/src/mxfs.1/`, `~/src/mxfs.2/`, `~/src/mxfs.3/` — design docs,
populated awareness corpus (mxfs.1 only), per-module changelogs, scale tests.
**Why this exists:** v5 (`/src/mxfs`) was started fresh against kernel XFS source
and did NOT inherit awareness docs, scaling benchmarks, or the bug journals from
the earlier iterations. Sess20-27 of v5 went in circles partly because that
prior-art corpus was not consulted. This dossier is a durable summary of what
mxfs.1-3 already knew, so future v5 sessions have a single reference.

**Scope:** Research, not architecture spec. Answers "what did mxfs.1-3 know?"

---

## TL;DR — the load-bearing finding

**Every "novel" v5 sess20-27 bug is a re-discovery of a bug mxfs.1 already
fixed in 2026-02 / 2026-03.** The fixes don't transfer cleanly because v5
sits on top of kernel XFS code (xfs_buf, xfs_inode, AIL, scsi_execute_cmd)
whereas mxfs.1's fixes were in mxfs's own caches (libmxfs/block_cache.c,
inode_cache.c, dir_cache.c) which were designed for DLM-aware invalidation.

The architectural decision to switch from "mxfs owns every cache" (mxfs.1)
to "use kernel XFS caches and hook the DLM into them" (mxfs.3 plan, v5
implementation) was made for **performance**. mxfs.1 was 4x slower than
native XFS even after 73 sessions of optimization. mxfs.3's bet was that
forking kernel XFS would close the perf gap. The bet succeeded on perf
(v5 single-node ≈ 1.5x of native XFS) but reintroduced an entire class
of cluster-coherency bugs that mxfs.1's owner-of-every-cache design had
explicitly avoided.

This was foreseen, not surprising. mxfs.1's `docs/architecture.md` line 68
contrasts "stacking FS: BAST tries to invalidate XFS caches externally"
against "MXFS Native I/O: BAST flushes and drops our own caches directly".
v5 is in the "stacking" column.

---

## 1. Architectural premises (mxfs.1)

### Core design (`mxfs.1/docs/architecture.md`, `mxfs.1/README.md`)

mxfs.1 is a multi-platform clustered filesystem (Linux/macOS/Windows) that
reads and writes the XFS on-disk format directly through its own portable
C library (`libmxfs`). Single deliverable on Linux: `mxfs.ko`.

```
libmxfs/                Linux frontend       PAL
  xfs_format.c/h         mxfs_super.c          pal_linux_kern.c (kthread, bio)
  block_cache.c/h        mxfs_inode.c          pal_linux_user.c (pthread)
  inode_cache.c/h        mxfs_file.c           pal_macos.c     (planned)
  dir_cache.c/h          mxfs_dir.c            pal_windows.c   (planned)
  alloc.c/h              mxfs_main.c
  extent.c/h
  journal.c/h
  dlm.c/h, dlm_caw.c/h
  peer.c/h, discovery.c/h, lease.c/h, disklock.c/h, scsipr.c/h
  mount.c/h
```

### The decisive premise

> "MXFS uses a native XFS format I/O engine — it reads and writes XFS
> on-disk structures directly, with its own DLM-aware caching at every
> layer. When a BAST fires, MXFS can flush and invalidate any cached
> data because it owns every cache."
>     — `mxfs.1/docs/architecture.md` line 9

### Stacking-FS antipattern (explicitly rejected in mxfs.1)

| Stacking FS                          | mxfs.1 (Native I/O)                 |
|--------------------------------------|-------------------------------------|
| Mount XFS via vfs_kern_mount()       | Read/write XFS on-disk format directly |
| XFS owns block cache (xfs_buf)       | libmxfs owns block cache, DLM-aware |
| XFS owns inode cache (xfs_inode)     | libmxfs owns inode cache, DLM-aware |
| XFS owns directory parsing          | libmxfs parses XFS dir format directly |
| XFS owns allocation (inobt, AGF, AGI) | libmxfs manages allocation, AG-DLM  |
| BAST tries to invalidate XFS caches externally | BAST flushes/drops our own caches directly |
| sync_filesystem() for flush          | Direct writeback of dirty blocks we track |

(`mxfs.1/docs/architecture.md` lines 60-69)

### What "owns every cache" bought mxfs.1

A clean BAST sequence (per `mxfs.1/.claude/awareness/subsystems/dlm.md`
lines 586-594, 728-741):

```
BAST arrives at holder
  → bast_worker thread queues
  → flush dirty blocks for THIS resource
  → commit journal
  → drop cache entries for this resource
  → mxfs_dlm_unlock()
  → master promotes waiters in FIFO
```

The seven invariants (mxfs.1 dlm.md lines 728-741):
1. No lock released until dirty data flushed.
2. Per-inode lock caching — held until BAST/eviction/unmount.
3. Pending entry inserted BEFORE BASTs are fired (avoids lost-grant race).
4. table_rwlock released BEFORE calling bast_cb (avoids deadlock).
5. BAST targets captured into snapshot under table_rwlock (chain corruption at 3+ nodes).
6. Grant epoch echoes requester's epoch.
7. MXFS_DLM_RETRY never escapes external callers.

### Final mxfs.1 status (per its own README)

- **116 bugs identified and fixed across 35 development sessions. No known
  open bugs remain.** (`mxfs.1/README.md` line 113)
- **32-node CAW DLM (VMs): 32/32 mounted, 1541/1600 metadata ops (96.3%), 0 errors.** (line 107)
- 8-node aggregate write throughput: 1,714 MB/s, 0 corruption.
- Single-node final perf (after Round 1+2 of perf opt): ~1.75x of native XFS
  on read AND write (`mxfs.1/docs/perf.md` line 156).

In other words, **mxfs.1 was a working clustered filesystem.**

---

## 2. Architectural changes (mxfs.2 vs mxfs.1)

### Why mxfs.2 happened (`mxfs.2/NEWSYS.md`)

mxfs.2 is a "rewrite document" — a planning artifact for a from-scratch
restart. Its rationale was a list of bugs in mxfs.1's hand-written XFS code
that "should never have existed":

- **Bug 141**: hand-written allocator's btree traversal didn't properly
  remove allocated blocks. cntbt "silently dropped inserts when a leaf
  split was needed" — comment in code admitted this.
- Stale block data (unwritten extents incompletely implemented).
- AG metadata CRC corruption (chk_mxfs found 8 corrupt AGs). XFS's write
  verifier callbacks recompute CRCs automatically; mxfs.1 didn't have those.
- Block cache coherency (DLM AG lock movement; new btree cursor engine
  didn't invalidate anything).
- Three separate I/O paths (write_direct vs block cache vs page cache).
- io_uring concurrent extent map races (Bug 140).

The mxfs.2 plan: **replace mxfs.1's hand-written XFS code with code adapted
from `~/src/linux/fs/xfs/libxfs/`** (the portable userspace-friendly subset
shared between kernel and xfsprogs). Keep DLM/cluster/PAL/frontend.

### What mxfs.2 actually became (`mxfs.3/project.md` retrospective)

> **/src/mxfs.new (v0.3.2)** — Took xfsprogs/libxfs (the userspace utility
> library) + custom I/O paths + DLM hooks. 78K lines of xfsprogs libxfs +
> 22K lines of MXFS-native code. Single-node fio benchmark: **45x slower
> than native XFS on writes**. Root cause: xfsprogs libxfs is a format
> library for mkfs/fsck, NOT the kernel XFS I/O engine.

mxfs.2 swapped the format/btree code for xfsprogs libxfs but kept hand-
rolled I/O paths around it — and the I/O paths (sync `submit_bio_wait()`
per buffer) were the actual perf bottleneck. mxfs.2 ended up worse than
mxfs.1 on perf.

### NEWSYS.md non-negotiable invariants

`mxfs.2/NEWSYS.md` lines 256-271 — explicit design principles for the
rewrite (these were carried into mxfs.3 / v5):

1. **ONE buffer cache path** — all I/O through one cache with write verifiers.
2. **Write verifiers on every buffer write** — auto CRC recompute.
3. **Unwritten extents from XFS** — don't reimplement.
4. **AG cache invalidation on lock acquire** — when DLM AG lock acquired
   from another node, ALL cached buffers for that AG invalidated before
   any read. **Non-negotiable.**
5. **DLM locks are the ONLY cross-node synchronization** — XFS handles
   single-node correctness, DLM handles multi-node serialization.
6. Frontend unchanged.
7. io_uring safety — per-inode serialization required.

Note line 4: this was already known to be "non-negotiable" in March 2026.
Whether v5 actually implements it comprehensively is open.

---

## 3. Architectural changes (mxfs.3 vs mxfs.2 vs mxfs.1) — and v5's premise

### `mxfs.3/project.md` is THE document for v5's architectural premise

Dated 2026-03-22. It assesses both predecessors and recommends the path
that became v5:

| Iteration             | Approach                                | Single-node overhead vs XFS |
|-----------------------|-----------------------------------------|----------------------------|
| ~/src/mxfs (v0.14.0)  | Hand-rolled libmxfs + DLM (= mxfs.1)    | 4.1x (after 73 sessions)   |
| /src/mxfs.new (v0.3.2)| xfsprogs libxfs + custom I/O paths + DLM | 45x                       |
| **Recommended**       | Fork `~/src/linux/fs/xfs/` + DLM hooks  | "Near-native"              |

The kernel XFS engine has the things mxfs.1 lacked (project.md line 38):
async I/O via xfs_buf, iomap-based page cache integration, async log,
6 dedicated workqueues, transaction batching, writeback infrastructure.
mxfs.1 had none of those — it was synchronous, single-threaded I/O.

### project.md's three options (lines 116-183)

- **Option A**: Linux-only kernel module forking `fs/xfs/`. **Precedent:
  GFS2 and OCFS2 are exactly this pattern — kernel-native clustered
  filesystems with their own DLM. They just use their own on-disk
  formats.** (line 142)
- Option B: Multi-platform via PAL abstraction over kernel XFS code.
  Rejected: iomap is too tightly bound to Linux page cache to abstract.
- **Option C: Linux-only loadable kernel module (Recommended)** — same
  as A but built as out-of-tree. This is what v5 became.

### The architectural invariants project.md says must carry forward

(lines 220-237 — "These were learned the hard way across 73+ sessions")

1. **No lock released until dirty data flushed** — BAST handler must
   flush dirty buffers, commit journal, drop cache, THEN release lock.
2. **Per-inode lock caching** — hold until BAST/eviction/unmount.
3. **AG affinity** — `preferred_ag = node_slot % ag_count`.
4. **Transport auto-detection** — listen 3s for peers, adopt their transport.
5. **Sector-granularity SB writes** — XFS SB is 512B in a 4K block.
6. **Block cache flush BEFORE inode cache flush** — prevent stale 4K
   cluster blocks overwriting fresh 512B inodes.
7. **TCP keepalive (19s) MUST be faster than DLM lock timeout (30s)**.

### Where v5's DLM hooks go (project.md lines 122-129)

- `xfs_buf.c` — flush dirty buffers on BAST, invalidate on remote write
- `xfs_inode.c` / `xfs_icache.c` — DLM lock around inode access
- `xfs_trans.c` — coordinate transaction commits with DLM
- `xfs_log.c` — per-node log slots, cross-node journal replay
- `xfs_super.c` — discovery, peer mesh, DLM init at mount

### Why this is structurally harder than mxfs.1

mxfs.1's design: "MXFS owns every cache, BAST flushes/drops directly."
v5's design: "Kernel XFS owns the caches, MXFS hooks the DLM and tries
to invalidate kernel caches at the right moments."

mxfs.1 had strongly-typed cache structures designed from day one to be
DLM-aware: every `mxfs_cached_inode` carries lock_mode, lock_gen,
dlm_epoch, bast_pending, bast_yield_remaining, pinned_inode, etc.
v5's `xfs_buf` and `xfs_inode` were designed for single-node and don't
have these fields. v5 must keep parallel state and try to keep it
synchronized — exactly the complexity the mxfs.1 architecture.md
section "Stacking FS vs Native I/O" warned against.

---

## 4. Concrete scaling evidence: TCP vs CAW

(Cross-referenced from `mxfs.1/README.md`, `architecture.md`, `bench.json`,
`scale_tests_session10.txt`, `libmxfs/lease.md`, `libmxfs/mount.md`)

### TCP DLM

- **Tested to 32 nodes**, recommended max 16. README line 304:
  "Network messages, per-resource lock master | 16 (tested to 32) |
  Storage without CAW support (e.g., NAS appliances)".
- **Correct at 32 nodes** (zero crashes, zero data corruption) but only
  **27% metadata completion** due to single lock-master-per-resource
  serial bottleneck. Lock wait times exceed VFS timeouts → I/O errors.
  (`architecture.md` lines 440-450)
- 100% metadata completion at 16 nodes.
- `bench.json`: TCP DLM has 6.5x-7.7x per-node write spread at 4+ nodes.
- `lease.md` line 35: "At 16+ nodes the DLM creates 120 TCP peer
  connections. Heavy DLM traffic fills send buffers, blocking lease
  renewal sends, causing false node-death cascades." → mxfs.1 moved
  heartbeats off TCP to UDP multicast specifically to fix this.
- `mount.md` line 189: `check_tcp_scale_warning` emits one-shot dmesg
  warning recommending CAW above 16 TCP DLM nodes. Already in mxfs.1 code.

### CAW DLM

- **Designed to 64 nodes**, README line 303. Tested to 32 (96.3% metadata).
- `bench.json`: CAW DLM shows 1.01x per-node write spread (vs TCP's 7.7x)
  on identical hardware.
- Per-resource locking on disk via SCSI Compare-And-Write — no master node,
  no serial bottleneck.
- `scale_tests_session10.txt`: at 8 nodes, CAW BAST polling (50ms)
  generates ~160 IOPS just for housekeeping; on a single-NVMe iSCSI target
  this saturates the LIO target. Mitigations: poll-frequency reduction,
  BAST yield quantum (`MXFS_BAST_YIELD_QUANTUM = 32` — see Bug 77).

### User's verbal characterization vs documented evidence

User said sess28: *"TCP saturates and begins to lose packets. Right around
24 nodes it completely falls off and the entire cluster fails."*

The documented evidence is more specific:
- TCP is **correct at 32 nodes** (no data loss) but unusable in production
  due to (a) serial lock-master bottleneck causing lock-wait-timeout I/O
  errors, and (b) TCP send-buffer congestion under heavy DLM traffic
  causing false-death cascades via blocked lease renewals.
- Spirit is right (TCP doesn't substitute for CAW at production scale);
  mechanism is more specific than "packet loss". And the failure does NOT
  manifest as a hard cluster-down event — it manifests as poor performance
  with rising error rates.

CAW is unambiguously the production primary for >16-node clusters.
Sess28's CAW-persistence focus is correct.

### Hardware-specific gotcha (mxfs.1 dir_cache.md line 142)

> "VMware multi-writer I/O coherency improvements... VMware multi-writer
> VMDKs sometimes serve stale data on the first read — missing entries
> recently written by other nodes."

mxfs.1 worked around this with FUA writes for all directory data blocks
and SYNCHRONIZE CACHE before reads (`mxfs_pal_bdev_write_fua()`,
`mxfs_pal_bdev_flush()`). **This is exactly the same shape of bug as
sess26 P49-INSTR's "scsi_execute_cmd CAS-success but write not
persisted"** — kernel SCSI says success, peer reads stale. mxfs.1
sidestepped it with FUA on every persistence-critical write.

---

## 5. The mxfs.1 bug catalog — Mode A and family

mxfs.1 hit and fixed essentially every Mode-A-class bug v5 sess20-27 has
been chasing. Source: `mxfs.1/libmxfs/dir_cache.md` (lines 113-152) and
`inode_cache.md` (lines 121-151). Bug numbers refer to mxfs.1's
internal bug tracking.

### Directly relevant to v5's Mode A (dir entries lost across release/reload)

| Bug   | Symptom                                                        | Root cause                                                              | Fix shape                                                              |
|-------|----------------------------------------------------------------|-------------------------------------------------------------------------|------------------------------------------------------------------------|
| BUG-G | block-format dir entries invisible cross-node                  | BAST callback only flushed shortform, not block-format                  | flush both formats before drop                                         |
| BUG-I | 4-node mkdir: 156/200 entries (44 lost)                        | BAST handler raced with mkdir on cd->entries linked list                | wait for refcount drain before BAST flush+free                         |
| BUG-R | cross-node dir visibility broken                               | BAST handler flushed STALE cached entries, overwriting peer changes     | **eager flush on every add/remove/rename; BAST DROPS, doesn't flush**  |
| Bug 3 | files invisible cross-node when dir cache pre-populated        | BAST arrives at refcount > 0; deferred eviction not honored             | invalidated flag + drain+evict on put_dir last-ref                     |
| Bug 44 | concurrent multi-node create: 30/200 lost as orphan inodes     | BAST during add_entry triggers retry; retry sees flushed entry, ENOEXIST + free | check flush rc; if flush succeeded, return success regardless of BAST |
| **Bug 49** | **4 nodes × 200 files = 515/800 unique + 152 dupes (= MODE A)** | get_dir_mode released inode ref before flush; DLM EX could be stolen between get_dir_exclusive and flush_dir_immediate | **`pinned_inode` field — keep inode pinned for entire dir access**     |
| Bug 49b | 800 touches → 208 files on disk                               | NL→EX upgrade re-acquired DLM but didn't reload inode metadata; stale extent map | load_inode_from_disk after any unlock+relock                           |
| Bug 50d | membership change overwrites correct disk with stale entries | dir_cache_flush_all during membership flushed stale subset over peer's data | `mxfs_dir_cache_discard_all()` (no flush) on membership change         |
| **Bug 50f** | **2 nodes × 500 files: each sees only ~500**                  | block_cache for dir data blocks survived inode_cache eviction; stale blocks served on reload | **invalidate block cache for ALL data extents at top of load_dir_from_disk** |
| Bug 50g | lock_gen check gated on refcount==0; concurrent holders escaped check | lock_gen mismatch silent for concurrent holders                  | wait+evict regardless of refcount path                                 |
| Bug 51 | flush_leaf_dir reallocation loses cross-node data              | each node freed and re-allocated extent from own AG; last writer wins   | KEEP existing extent, only allocate additional blocks                  |
| Bug 53 | dirs > 502 entries permanently lost                            | leaf block overflow truncated entry count                              | implement node-format writeback                                        |
| Bug 58b | flush of invalidated dir cache produced cross-node loss        | flush after BAST set invalidated=true wrote stale data                  | epoch + invalidated guards in flush_dir_immediate                      |
| Bug 60 | 4-node concurrent metadata: ~20-30% silent data loss           | VMware VMDK cache coherency + every-EX evict/reload amplification       | EX fast path (skip evict if lock_gen unchanged) + FUA + dedup-on-load  |
| **Bug 76** | **dirty dir entries lost during BAST → unmount overwrites peer's data** | complete_bast flushed inodes but not dir cache before DLM release | **mxfs_dir_cache_flush_ino() called from complete_bast before unlock** |
| **Bug 77** | **BAST yield quantum doesn't actually yield**               | quantum 1→0 didn't trigger complete_bast; thread polled forever         | **explicit complete_bast call when quantum exhausted at refcount==0**  |

### Inode-side bugs in the same family (`mxfs.1/libmxfs/inode_cache.md`)

| Bug   | Symptom                                                        | Fix shape                                                              |
|-------|----------------------------------------------------------------|------------------------------------------------------------------------|
| Bug 45 | retry-with-backoff caused duplicate dir entries + D-state      | rely on 120s DLM timeout, not retries                                  |
| Bug 48 | UAF in epoch mismatch eviction                                 | if refcount > 0, release+reacquire in-place; only free when refcount==0 |
| Bug 50e | stale inode after PR→EX upgrade                               | always reload inode after any unlock+relock                            |
| Bug 54 | DLM grant vs BAST race → phantom EX cached lock (dual-EX!)     | `pending_bast_ino` + `inflight_lock_ino` tracking                      |
| Bug 55 | slab corruption from leaked extents on reload                  | free old extents/inline_data at top of load_inode_from_disk            |
| Bug 56 | complete_bast UAF from concurrent ci access                    | pin during flush, skip upgrade if bast_pending, recheck refcount       |
| Bug 58a | epoch-mismatch handler downgraded EX→PR silently              | re-acquire at MAX(ci->lock_mode, requested_mode)                       |
| Bug 75 | BAST deadlock on orphaned DLM lock after membership change     | inflight_lock_ino tracking; release immediately if no in-flight call   |
| VMware fix | inode flush write+flush insufficient on VMDKs              | **FUA write per inode (mxfs_pal_bdev_write_fua)**                      |
| 2026-03-19 | EX→PR downgrade after write so peers can read sooner       | `mxfs_inode_lock_downgrade` after filemap_write_and_wait              |

### Pattern observation

These bugs are not random — they cluster into about five archetypes:

1. **Lock state machine errors** (Bug 45/48/56/58a/54/75) — DLM lock state
   and cached inode state diverge. Need rigorous state tracking + always
   reload metadata after any unlock+relock.
2. **Cache invalidation gaps** (Bug 50f, BUG-G, BUG-R) — caches at level
   N persist past invalidation at level N+1. Need to invalidate ALL
   layers on lock acquire from another node.
3. **Race windows between DLM acquire and use** (Bug 49, Bug 49b, Bug 76, Bug 77) —
   between get_lock and use_data, lock can be stolen. Need to PIN the resource
   for the duration of use, and ensure BAST handler actually completes
   before another acquire.
4. **Membership-change overwrites** (Bug 50d, drop_all) — flushing stale
   cached state during membership reconfig overwrites peer's correct
   on-disk state. Need DISCARD (drop without flush) at membership change,
   not flush.
5. **VMware/SCSI cache coherency** (VMware fix, Bug 60) — kernel I/O
   completes "successfully" but peer reads stale. Need FUA writes +
   pre-read SYNCHRONIZE CACHE.

**Sess28's three open bugs map onto these:**

- v5 Bug 1 (`scsi_execute_cmd` CAS-success / write not persisted) = archetype 5.
- v5 Bug 2 (Mode A) = archetypes 1+2+3 simultaneously.
- v5 Bug 3 (AIL deadlock) = unique to v5 (mxfs.1 didn't have an AIL).

---

## 6. mxfs.3 session 64 — Mode A surfaced AT BIRTH

`mxfs.3/journal.md` is a single mega-session (Session 64, 2026-03-?) where
the entire v5-style filesystem was built from kernel XFS in one sitting
(~9000 lines). Cross-node mode came online around 15:42, and within 8
minutes of it being functional, **Mode A surfaced**:

```
15:50 — Concurrent write test
- Both nodes create 5 files simultaneously
- N1 sees its 5, N2 sees 9 of 10 — some lost entries from concurrent dir modification
- Issue: DLM EX acquire/release per-op has race window during rapid concurrent access
- Fix: hold DLM lock longer (lock caching), release on BAST — this is how mxfs.old works
```

Later in the same session (lines 369-414):

```
4 concurrent dd writers → all fail md5 after remount
Sequential writes work
Root cause: VFS writeback thread + concurrent alloc_file_block race
mpage_writepages + concurrent write_begin race corrupts block mapping
"This is a fundamental issue that real XFS solves with its transaction
 system and exclusive inode lock held through the entire write path"
"The old system [mxfs.1] serialized writes through the DLM inode lock
 (held for entire write operation)"
KNOWN LIMITATION for v0.3.0
```

And mxfs.3's last journal entry (line 794):

```
8-node CAW DLM cluster: 8/8 mounted sequentially, all with auto-detected CAW.
Cross-node file visibility confirmed. Concurrent directory writes from 8
nodes lose entries (directory serialization under heavy contention —
known limitation).
```

**Mode A was identified, characterized, and labeled "known limitation"
at the very moment mxfs.3 cluster mode came online.** v5 inherited it
explicitly. Sess20-27 have been chasing this exact bug for ~8 sessions
without referring back to this clearly-recorded analysis. The fix
direction has been known the whole time: full BAST protocol with
proper lock caching, mxfs.1-style.

---

## 7. Synthesis: answers to the five questions

### Q1 — Is sess26 P49-INSTR's `scsi_execute_cmd` CAW non-persistence under stress a known issue from mxfs.1/2/3?

**Yes — same family of bug, different surface.**

mxfs.1 hit "kernel I/O reports success but peer reads stale" repeatedly
on VMware multi-writer VMDKs (`dir_cache.md` 2026-02-27 line 142,
`inode_cache.md` 2026-02-28 line 138). The fix mxfs.1 used everywhere
persistence was critical: `mxfs_pal_bdev_write_fua()` instead of
`bdev_write + bdev_flush`. FUA atomically guarantees the write reaches
stable storage.

Sess26's P49-INSTR finding is the same shape: kernel CAS reports success,
peer FUA-read returns stale or pre-CAS bytes. caw_verify (userspace
SG_IO) under same load returns 0 divergence in 4430 + 3839 iters.

**Practical implications for sess28:**

(a) The bug is in the kernel SCSI passthrough (`scsi_execute_cmd`) +
LIO target / virtio-scsi cache layer interaction, not in MXFS logic.
mxfs.1's solution (FUA per-write) is the workaround that makes this
bug irrelevant. The current v5 path probably needs FUA equivalents
on every persistence-critical CAW write. Investigate whether MXFS_CAW
already uses FUA — sess28's `dlm/dlm_caw.c` review.

(b) The kernel-vs-userspace divergence (`scsi_execute_cmd` broken,
SG_IO works) is a real kernel bug worth root-causing. mxfs.1's
`pal_linux_kern.c` has the kernel SG_IO path; comparing the two
request setup code paths byte-by-byte is exactly what sess28's
state.md recommends.

### Q2 — Has mxfs.1 already characterized an equivalent of "Mode A"?

**Yes — at least 16 distinct Mode-A-class bugs were identified and fixed in mxfs.1.** See section 5 above.

The closest direct match to v5's Mode A is **mxfs.1 Bug 49**
(`dir_cache.md` 2026-02-23): "4 nodes creating 200 files each
produced only 515/800 unique files with 152 duplicates."

Bug 49's root cause: `get_dir_mode(exclusive=true)` released the inode
cache reference before returning, allowing the DLM EX lock to be
released between `get_dir_exclusive` returning and `flush_dir_immediate`
being called. Another node could acquire EX, modify dir, flush. When
original node's flush re-acquired EX, it wrote stale cached entries,
overwriting peer changes.

Fix: `pinned_inode` field on `mxfs_cached_dir`. When dir obtained with
EX access, the underlying inode cache entry stays pinned (refcount > 0)
for the entire duration, preventing BAST from releasing the DLM EX lock.

**v5 cannot use mxfs.1 Bug 49's fix verbatim** because v5 doesn't have
mxfs_cached_dir — it has kernel XFS's `xfs_dabuf` and `xfs_buf` for
directory blocks. The structural equivalent in v5: the AG/inode DLM
hold must span the entire kernel-XFS directory operation, not just
the lock acquire/release call site. Whether v5 currently does this
comprehensively is the central sess28 question.

### Q3 — Did mxfs.1 ever hit the AIL deadlock, and how was it solved?

**No. mxfs.1 didn't have an AIL.** mxfs.1 used its own libmxfs/journal.c +
block_cache + inode_cache. The AIL is a kernel-XFS construct that v5
inherited from forking `~/src/linux/fs/xfs/`.

mxfs.1's analog of "drain pending writes on lock release" was
`mxfs_block_cache_flush_range()` (per-resource, scoped to the block
cache entries for THIS lock), not a whole-FS drain. The natural shape
of "flush only what this lock owns" maps cleanly onto per-AG or
per-inode AIL drain in v5 — exactly the GFS2 `gfs2_ail_empty_gl(gl)`
pattern from `~/src/linux/fs/gfs2/glops.c::inode_go_sync`.

**For v5 sess28's Bug 3:**

Sess27 already identified that `xfs_ail_push_all_sync` at 5×512MB causes
both nodes' bast workers to deadlock (AIL contains items from other
glocks). Sess27 tried bounded timeout — broke correctness. The correct
fix shape (matching both GFS2 and the spirit of mxfs.1's per-resource
drain) is **per-AG AIL drain filtering by AG/owner**, not bounded-time
whole-AIL drain.

### Q4 — Why did v5 start fresh, and is the bug a regression from that decision?

**v5 started fresh for performance** — see `mxfs.3/project.md` (section
3 above). mxfs.1 was 4.1x slower than native XFS even after 73 sessions
of optimization; mxfs.3 bet that forking kernel XFS would close the
gap. The bet on perf succeeded.

**Yes, the current bugs are largely a regression from that decision.**
mxfs.1's `architecture.md` explicitly contrasted two architectures
(stacking-FS vs native-I/O) and explicitly chose native-I/O *because*
the stacking-FS approach has the problem v5 is now hitting:

> "Stacking FS: BAST tries to invalidate XFS caches externally"
> vs.
> "MXFS: BAST flushes and drops our own caches directly"

v5 is in the stacking column structurally. The kernel XFS caches
(xfs_buf, xfs_inode page cache, AIL) were not designed to be invalidated
externally on cluster lock state changes. v5 is doing that anyway, and
the bugs are exactly the kind mxfs.1's design avoided by owning the caches.

**This is not a reason to revert to mxfs.1.** The perf gap was real
and untenable for production. But it does mean:

(a) The cluster coherency contract for v5 is structurally harder than
mxfs.1's was — every fix must navigate kernel XFS internals.

(b) The right model is **GFS2** (which mxfs.3/project.md cites as
precedent at line 142). GFS2 made the same architectural choice (fork
kernel filesystem code, add DLM hooks) and built rigorous per-glock
release/invalidate machinery (`inode_go_sync`, `inode_go_inval`,
`gfs2_ail_empty_gl`, `GLF_INSTANTIATE_NEEDED`). GFS2's contract is
the model v5 should aim at, NOT mxfs.1's contract.

### Q5 — What does mxfs.1 do on lock release/demote that v5 might be missing?

The 16-bug list in section 5 is the menu. Mapping those fixes onto v5's
kernel-XFS substrate is the actual sess28+ work. The high-leverage ones:

**On lock release / BAST (matches mxfs.1's `complete_bast` + Bug 76):**

1. Flush dirty AG metadata buffers (xfs_buf entries for AGF/AGI/btree blocks
   for this AG) — v5 has this in some form.
2. Force AIL drain SCOPED TO THIS AG/INODE (not whole AIL) before release —
   Bug 3 fix needed.
3. **Flush dirty directory data blocks** (the xfs_buf entries holding the
   dir block — equivalent of mxfs.1 dir_cache pre-flush). Whether v5 does
   this comprehensively for kernel XFS's directory I/O path is unclear
   from the sess20-27 history.
4. Use FUA on the writes that other nodes will read (= mxfs.1 Bug VMware
   fix). This may be Sess28's first-line workaround for Bug 1.
5. Issue blkdev_issue_flush AFTER the writes (= mxfs.1 SYNCHRONIZE CACHE
   pre-read on the reader side, but applied on writer for symmetry).
6. Release DLM lock LAST.

**On lock acquire from another node (matches mxfs.1's load_inode_from_disk
+ block_cache invalidation, BUG-R + Bug 49b + Bug 50f):**

1. Invalidate ALL `xfs_buf` cache entries for the AG/inode being acquired.
   This is "non-negotiable" per `mxfs.2/NEWSYS.md` line 168.
2. Invalidate kernel XFS's inode page cache for inodes whose data extents
   may have changed (peer may have written to file).
3. **Invalidate kernel XFS's directory cache for any directory whose
   contents could have changed** (= mxfs.1 BUG-G/BUG-R/Bug 50f equivalent).
   v5 needs to find the right kernel XFS hooks.
4. Force a SYNCHRONIZE CACHE (issue empty FUA read) to flush the SCSI
   target's read cache for this LBA range, before reading data. This is
   the symmetric counterpart of writer-side FUA.
5. Re-read everything from disk before serving the cached data.

**Pinning during use (matches mxfs.1 Bug 49 `pinned_inode`):**

1. While performing a multi-step operation (e.g., directory create:
   acquire EX → read dir → modify → flush), the AG/inode DLM lock must
   not be released by BAST. Either suppress BAST during the operation
   (with a deadline so it doesn't starve peers) or, equivalently,
   ensure all operations complete before BAST is honored.
2. The BAST yield quantum (`MXFS_BAST_YIELD_QUANTUM = 32`, see Bug 77)
   is mxfs.1's mechanism for amortizing BAST cost without starving peers.
   v5 may need an equivalent.

**State machine invariants (matches mxfs.1 Bug 48/50e/54/56/58a/75):**

1. After any unlock+relock cycle (NL→PR, NL→EX, PR→EX), reload inode
   metadata from disk. Without this, cached extent maps + sizes go
   stale silently.
2. Track in-flight DLM lock requests (`inflight_lock_ino`) so BAST that
   arrives between LOCK_REQ and cache-entry-creation isn't lost or
   handled as orphan.
3. On membership change, DISCARD cached state without flushing
   (mxfs.1 Bug 50d). v5 has TCP DLM membership stabilizer carried
   from sess27 — verify it doesn't flush stale on transitions.
4. Epoch tracking — every cached lock carries the epoch at which it
   was acquired; mismatch = stale, evict + re-acquire.

---

## 8. Recommended actions for sess28+

In rough priority order:

### Immediate (within sess28)

**A. Re-enable P49-INSTR and reproduce the SCSI persistence bug under
default CAW** (state.md sess28 plan). This is uncontroversial and
gives concrete kernel-vs-userspace divergence trace.

**B. While the trace runs, audit `dlm/dlm_caw.c` for FUA usage.**
Question: does v5's CAW write path use FUA, or is it `scsi_execute_cmd`
WRITE-and-then-`blkdev_issue_flush`? mxfs.1 found the latter pattern
unreliable on VMware multi-writer + LIO and switched everywhere to
explicit FUA. If v5's CAW writes don't already use FUA (check both
the slot writes and the metadata writes the BAST handler does),
that's a strong candidate for Bug 1's actual workaround.

**C. Consult `mxfs.1/.claude/awareness/subsystems/dlm.md` lines 586-741
as a reference for the canonical BAST flow** before re-instrumenting.
Compare v5's bast_process step-by-step against that flow and note
gaps.

### Near-term (sess28-30)

**D. Per-AG AIL drain (Bug 3).** Replace `xfs_ail_push_all_sync` in
`mxfs_dlm_ag_bast_work_fn` with a per-AG filter. Reference: GFS2
`gfs2_ail_empty_gl(gl)`. Sess27's `xfs_ail_push_all_sync_timed` stub
in `xfs/xfs_trans_ail.c` is the wrong shape (timeout, not filter);
discard or replace.

**E. AG cache invalidation audit on lock acquire** (`mxfs.2/NEWSYS.md`
"non-negotiable" item 4). Walk every `mxfs_dlm_lock` callsite that
acquires an AG lock and verify that ALL kernel `xfs_buf` cache entries
for that AG's metadata blocks are invalidated before proceeding. This
is the structural Bug 50f equivalent for v5.

**F. Directory read coherency.** v5's directory entry loss (Mode A) is
likely missing one or both of:
   - On AG/inode lock acquire: invalidate `xfs_buf` entries for the
     directory's data extents (Bug 50f equivalent).
   - On AG/inode lock release: flush dirty `xfs_buf` entries for those
     extents using FUA (Bug VMware fix equivalent).

### Medium-term (after sess30)

**G. Build the v5 coherency contract as a written document in
`/src/mxfs/docs/`** matching the level of detail in
`mxfs.1/.claude/awareness/subsystems/dlm.md`. Cross-reference against
GFS2's `inode_go_sync` / `inode_go_inval`. This becomes the spec
that fixes are tested against.

**H. Bootstrap project awareness for v5** (deferred per user direction
in sess28). Use `mxfs.1`'s populated `.claude/awareness/` as a template,
but adapted for v5's kernel-XFS-fork architecture.

### Don't do

- Don't propose abandoning v5 to revert to mxfs.1. The perf gap was
  the reason v5 exists, and mxfs.1's design ceiling is a known 4x
  overhead on single-node which is untenable for production.
- Don't propose abandoning CAW for TCP DLM. Documented evidence is
  unambiguous that TCP doesn't scale past 16 nodes (see section 4).
- Don't propose new architectures while the existing one has known
  fixes (per the menu above) that haven't been tried.

---

## 9. Appendix: file inventory (read during sess28 research)

### Read in full
- `~/src/mxfs.1/README.md`
- `~/src/mxfs.1/docs/architecture.md`
- `~/src/mxfs.1/docs/dlm-protocol.md`
- `~/src/mxfs.1/docs/perf.md`
- `~/src/mxfs.1/libmxfs/dir_cache.md` (152 lines, the bug catalog)
- `~/src/mxfs.2/NEWSYS.md`
- `~/src/mxfs.3/project.md`

### Read partially / heavily skimmed
- `~/src/mxfs.3/journal.md` (~500 of 801 lines — through session 64 v0.3.2)
- `~/src/mxfs.1/.claude/awareness/subsystems/dlm.md` (head + key BAST sections)
- `~/src/mxfs.1/libmxfs/inode_cache.md` (changelog from line 100)
- `~/src/mxfs.1/scale_tests_session10.txt` (full)
- `~/src/mxfs.1/scale_test_6node.txt` (head)

### Cross-referenced via grep but not opened
- `~/src/mxfs.1/handoff.md`
- `~/src/mxfs.1/libmxfs/{dlm,lease,peer,mount}.md`
- `~/src/mxfs.1/libmxfs/lease.c`, `mount.c`, `block_cache.c`
- `~/src/mxfs.1/.claude/awareness/structural-map.md` (2916 lines, deferred)
- `~/src/mxfs.1/.claude/awareness/subsystems/{cluster,platform-vfs}.md` (deferred)
- `~/src/mxfs.1/bench.json`, `mxfs.2/mxfs_bench.json`, `mxfs.3/bench.json`

### Not yet consulted (low priority for this dossier; useful future reference)
- `~/src/mxfs.1/TASKS.md`, `TEAM.md`, `INFO.md`, `FIX.md`, `refactor.md`
- `~/src/mxfs.1/p`, `~/src/mxfs.3/r/`, `~/src/mxfs.3/scripts/`
- `~/src/mxfs.{1,2,3}/tools/`, `tests/`
- `~/src/mxfs.wtf/`, `~/src/mxfs.x/` (status unknown — likely failed branches)
