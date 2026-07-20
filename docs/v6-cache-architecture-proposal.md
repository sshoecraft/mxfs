# MXFS v6 Cache Architecture Proposal

**Author**: sess31 research (2026-05-07)
**Status**: DESIGN PROPOSAL — not yet committed.  Sess32+ may revise after measurement.
**Supersedes**: nothing yet.  Lives alongside v5 spec
(`docs/mxfs-architecture-spec.md`) until a v5-vs-v6 path decision is made.

---

## 0. Reading order

This document is organized so a future implementation session can act
without re-deriving the design.  If you only have ten minutes:

- **§1** says what's broken.
- **§3** says what to build.
- **§8** says whether to build it.

The rest is the evidence.

---

## 1. Problem statement

### 1.1 The measurement (sess30, 2026-05-07)

A 4-test rsync sweep on the canonical hardware (clyde host, kernel
6.8.0-101, Samsung 870 EVO via tcm_loop + LIO iblock backstore + qemu
virtio-scsi-block, two libvirt VMs test1 and test2) produced this
result:

| Workload                          | Time             | Notes                                  |
|-----------------------------------|------------------|----------------------------------------|
| XFS native, open-gpu              | 3.12 s           | baseline                               |
| XFS native, element-web           | 2.56 s           | baseline                               |
| v5 v0.3.128 single-node, open-gpu | 3.47–3.72 s      | 1.1–1.2× XFS — **good**                |
| v5 v0.3.128 single-node, element  | 3.57–4.41 s      | 1.4–1.7× XFS — **good**                |
| v5 v0.3.128 2-node parallel       | KILLED at 9 min  | iter 1 hadn't finished                 |
| mxfs.1 v0.14.0 open-gpu           | 13 / 88 / 116 s  | degrading; clean                       |
| mxfs.1 v0.14.0 element-web        | CORRUPTION       | dir_cache format-transition bug        |

The 2-node v5 number is the central finding.  9+ minutes for what takes
3-4 s single-node is not a performance fluke.  It is the architecture
hitting a measured ceiling.

The same shape reproduces on the framework's `test_concurrent_write`
test (10×256 KB files per node, separate paths, then md5 cross-verify):
test2 was stuck 7+ minutes in cross-verify reading test1's files.
Same workload class — metadata-heavy with cross-node reads.

### 1.2 What is happening

While the 2-node rsync ran, both nodes were issuing approximately
**1024 SCSI READ(16) FUA per second per node**, ~600 µs each.  That
saturates the storage stack: each FUA read is a full LIO + QEMU +
iSCSI-loopback + block-layer round-trip, and on this hardware
`/sys/block/sda/queue/fua=0` so LIO's `target_core_iblock.c:772`
silently drops the initiator FUA bit, meaning the kernel fallback path
is invoked for every "FUA read".

There are two distinct failures bundled in this measurement, and the
proposal must address both:

**Failure A — implementation drift from the spec.**
Spec D6 (`docs/mxfs-architecture-spec.md:312-345`) says:

> When an AG or inode token is acquired from a peer, `mxfs_clayer` MUST
> explicitly invalidate ALL kernel-XFS cache state for that resource
> before kernel XFS reads it.  ...invalidate ALL `xfs_buf` entries for
> the AG's metadata blocks.

That spec is GFS2-shaped: per-resource invalidation at lock-acquire
boundaries, with the actual reads going through normal kernel XFS code
paths (page cache + xfs_buf cache).

What shipped in v0.3.114b and persists through v0.3.128 is different.
`mxfs_buf_needs_fua_read` and the related FUA-on-acquire hook turn
**every metadata read** that crosses the marked-stale boundary into a
SCSI READ FUA, not just the first read after lock acquisition.  The
xfs_buf cache is not used to amortize subsequent reads — the FUA tag
forces the storage layer to re-read every time.  This is closer to
mxfs.1's direct-bio model than to GFS2's invalidate-once model.

**Failure B — the spec is also expensive.**
Even if Failure A is fixed (invalidate-once on lock acquire, then let
the kernel page cache amortize subsequent reads while the lock is
held), the spec still requires that on cross-node lock movement, ALL
xfs_buf entries for the AG's metadata blocks are dropped and re-read.
For a metadata-create-heavy workload like rsync of a deeply-nested
source tree, the lock bounces frequently — every bounce is an O(AG
metadata size) read storm.  GFS2 amortizes this by holding glocks for
extended periods (yield quantum, lock caching) so the storm cost is
divided across many ops.  v5 has D10 yield quantum in the spec but
its current state is unclear.

So the **architectural question** is two layers deep:

1. Can v5 implement D6 as written (invalidate-on-acquire, not
   FUA-on-every-read), reaching a kernel-page-cache-amortized regime
   like GFS2?  This is implementation work, not redesign.
2. If yes, is that regime fast enough for production cross-node
   metadata-heavy workloads, or is there an architectural cost beyond
   it that requires a deeper change (LVB-style state caching à la
   OCFS2, or an asymmetric metadata-server)?

This document calls the (1)-only path **v6a** and the (2) path **v6b**.
We propose v6a as the first move and define the falsifying experiment
that decides whether v6b is needed.

### 1.3 What is NOT being asked

- This is not "scrap v5, start over."  The forked-XFS substrate
  (D2) is keeping single-node perf within 15-25% of native XFS, which
  is the entire reason v5 exists.  Whatever changes go in must preserve
  that.
- This is not "switch to TCP DLM and call it done."  TCP is correct
  to 32 nodes but performance-limited above 16 (`memory/
  project_caw_is_load_bearing.md`); CAW is the production primary.
  The cache architecture is transport-independent.
- This is not "go back to mxfs.1."  mxfs.1 has measured single-node
  corruption on element-web rsync (`reference_mxfs1_sess74_results.md`,
  `dir_cache.c` format-transition bug) and 4.3× perf overhead on
  rsync.  It is reference material, not a target.

---

## 2. Reference designs

For each design, the questions are:

- Where does metadata live?
- How is invalidation triggered on lock acquire?
- What does the BAST/release contract look like?
- Are reads amortized across many ops while a lock is held?
- What's the cost of multi-node concurrent metadata-create?
- Verdict for MXFS.

### 2.1 GFS2 — the canonical model

**Where metadata lives.**  Kernel page cache.  Each glock with the
`GLOF_ASPACE` flag has its own `address_space` (an in-kernel inode
created by `gfs2_aspace_get`); meta buffers live on pages in that
address space, indexed by block number divided by page size.
Source: `~/src/linux/fs/gfs2/glock.c::gfs2_glock_get` and
`~/src/linux/fs/gfs2/meta_io.c::gfs2_getbuf`.

**How invalidation is triggered.**  Per-glock-type `go_inval`
callback in the per-type `gfs2_glock_operations` table at
`~/src/linux/fs/gfs2/glops.c`.  `inode_go_inval` calls
`truncate_inode_pages(metamapping, 0)` on `DIO_METADATA` flag, which
evicts every buffer for that glock's metadata aspace.  `rgrp_go_inval`
(closest analog to MXFS's AG token) calls `truncate_inode_pages_range`
scoped to the resource group's block range.  These are called from
`do_xmote` at `glock.c:686-699` BEFORE the DLM lock-release request
is sent.

**BAST/release contract.**  The release sequence at `do_xmote` is:

```
spin_unlock(&gl->gl_lockref.lock);
glops->go_sync(gl);                    /* flush dirty: log_flush + AIL drain + filemap_fdatawrite + wait */
glops->go_inval(gl, target == LM_ST_UNLOCKED ? DIO_METADATA : 0);
spin_lock(&gl->gl_lockref.lock);
gfs2_glock_lock(gl, ...);              /* DLM call */
```

The invariant is: by the time the DLM lock is released, the local
cache contains nothing for that resource.  The next holder (anywhere
in the cluster) starts from a clean slate.

**Read amortization.**  This is the load-bearing part for the
rsync-bench scenario.  A node holding a glock in `LM_ST_SHARED` reads
metadata via `gfs2_meta_read`:

```
*bhp = bh = gfs2_getbuf(gl, blkno, CREATE);
lock_buffer(bh);
if (buffer_uptodate(bh)) {       /* CACHE HIT — no I/O */
    unlock_buffer(bh);
} else {                          /* miss — submit one bio */
    bhs[num++] = bh;
}
```

(`meta_io.c:259-276`).  The first read of a page incurs one bio; the
second through Nth reads of the same page hit the buffer cache layer
(no I/O).  Pages stay valid until `go_inval` evicts them — i.e., until
some peer requests a conflicting lock.  Amortization factor:
~`page_size / block_size`, typically 4-16×.

**Cost of cross-node concurrent metadata-create.**  Bounded by
yield-quantum-equivalent (held for many ops per acquire) +
amortization factor.  Empirically GFS2 handles rsync of nested trees
on shared hardware at ~1-3× single-node, not 200× as v5 currently
shows.

**Verdict for MXFS.**  This is the model.  Every architectural piece
of GFS2's coherency story has an analog in v5's spec — the gap is in
implementation, not in plan.  v5 D6 (invalidate on acquire) maps to
`go_inval`.  v5 D8 (per-AG AIL drain) maps to `gfs2_ail_empty_gl`.
v5 D9 (pinned resource) maps to GFS2's holder refcount.  v5 D10
(yield quantum) maps to glock hold time tuning.

### 2.2 OCFS2 — the LVB twist

**Where metadata lives.**  Hybrid.  Inode dinode blocks in the buffer
cache (BH).  Extent trees, xattrs, etc. in a separate per-inode
in-memory tree (`ocfs2_caching_info.ci_cache`, RB-tree-backed beyond
8 entries).  File content (data) in the page cache.  This means OCFS2's
metadata cache is NOT subject to page cache eviction policy — it's
explicitly managed per lock release.

**How invalidation is triggered.**  Per-lock-type ops table at
`fs/ocfs2/dlmglue.c:225-285`.  Unlike GFS2's unified `glops`, each
lock type has its own structure with only the callbacks it needs.  The
metadata lock's `downconvert_worker` is `ocfs2_data_convert_worker`
(`dlmglue.c:3941-3991`), which `unmap_mapping_range` + 
`filemap_fdatawrite` + `truncate_inode_pages` on EX downconvert.

**BAST/release contract.**  Similar to GFS2: flush before drop, drop
before DLM release.  Distinguishing detail: `check_downconvert`
(`dlmglue.c:4009-4015`) calls `ocfs2_ci_fully_checkpointed` and
*refuses* to allow downconvert until metadata is journaled.  This is
a stronger version of "no lock release before flush" — it's "no
release until journal-replay-safe."

**The LVB pattern (this is what makes OCFS2 distinctive).**
OCFS2's metadata lock declares `LOCK_TYPE_USES_LVB` (`dlmglue.c:236`).
On EX downconvert, `ocfs2_set_meta_lvb` (`dlmglue.c:4017-4022`,
implemented at `__ocfs2_stuff_meta_lvb` `dlmglue.c:2161-2199`) writes
inode size, cluster count, mode, nlink, uid, gid, timestamps INTO the
DLM lock's value block — a small (~64 byte) payload that the DLM
delivers atomically to whoever next acquires the lock.

When another node acquires the lock in PR or EX, it reads the LVB
(`dlmglue.c:2208-2250 ocfs2_refresh_inode_from_lvb`) and fills its
in-memory inode from those bytes — **no disk read needed** for stat
metadata.  Disk read is only needed for content (extent trees, dir
entries) that doesn't fit in the LVB.

**Cost of cross-node concurrent metadata-create.**  For workloads
where most cross-node access is stat-style (size/times/mode), OCFS2
avoids the disk-read storm entirely.  For workloads that read full
inode/extent trees, it still pays a disk round-trip on lock movement
— but because much metadata is in a separate tree managed
explicitly, OCFS2 has finer-grained control over what gets dropped vs
kept.

**Verdict for MXFS.**  The LVB pattern is an optimization on top of
GFS2-style invalidation.  We should NOT make it a primary design
mechanism (it doesn't fit MXFS's "fork kernel XFS" model — kernel XFS
doesn't have an LVB equivalent and bolting one on means modifying
xfs_inode), but it's an option for v6b if v6a measurements show
stat-metadata reads are the dominant cost.  Filed in §7 (open
questions).

### 2.4 mxfs.1 — direct-bio with custom caches

**Where metadata lives.**  `libmxfs/block_cache.c` (4 KB blocks),
`libmxfs/inode_cache.c` (per-inode), `libmxfs/dir_cache.c` (per-dir).
NOT in the kernel page cache.

**How invalidation is triggered.**  Per-resource (per-block,
per-inode, per-dir) on BAST.  `mxfs_block_cache_bast_handler(cache,
blockno)` looks up the single block, flushes if dirty, drops it.

**Read amortization.**  Single-block synchronous I/O via PAL's
`mxfs_pal_bdev_read` → `submit_bio_wait`.  No readahead beyond the
8-block heuristic added in sess73.  No page-cache-style amortization;
each cache miss is one bio, no merging.  Sess73 measured "650-860 r/s
at 4 KB during create phase, 0% merging, 80% util" — the 4.3× perf
overhead is exactly this.

**The unimplemented v6 plan.**  `~/src/mxfs.1/handoff.md:393-398`
identifies the fix:

> **Page-cache-based metadata I/O**: Replace block_cache direct reads
> with `read_mapping_page()`.  Biggest potential win (~15-20s).

This was never built.  It's the same fix GFS2 implemented in 2006.

**Verdict for MXFS.**  Reference for what NOT to do.  Direct-bio per
metadata block is the cliff that v6 must avoid.  But mxfs.1's bug
catalog (16+ Mode-A-class bugs, all fixed) is a load-bearing reference
for the correctness contract — every bug mxfs.1 fixed is a bug v6
must also avoid.

### 2.5 Ceph (CephFS) — for contrast

**Where metadata lives.**  Caps (capability bits) per inode, granted
by the MDS over the network.  Cap bits are like multi-class tokens but
delivered via async messages, not a shared DLM.

**Verdict for MXFS.**  Different problem domain (distributed object
store with metadata server cluster).  Not a viable model for MXFS's
shared-block-device topology.  Mentioned only for contrast; Ceph caps are
the same idea in a network-message system rather than a DLM system.
Not proposed.

### 2.6 Summary of viable models

| Model     | Metadata cache    | Invalidation | Read amort  | Cross-node MD-create cost | Suitable for v6 |
|-----------|-------------------|--------------|-------------|---------------------------|-----------------|
| GFS2      | Kernel page cache | Per-glock    | Page cache  | ~1-3× single-node         | **YES** — proposed |
| OCFS2     | Hybrid (BH+tree)  | Per-lock-type| Mixed       | ~1-3×                     | YES (alt., LVB augment) |
| mxfs.1    | Custom direct-bio | Per-resource | None        | 4.3× even single-node     | No — known cliff |
| Ceph      | Cap bits          | MDS message  | N/A         | N/A                       | No — different topology |

GFS2 is the model.

---

## 3. Proposed v6 cache architecture

We propose **v6a — implement v5 spec D6 as written, GFS2-shaped.**
We defer v6b (LVB-style state caching) to §7 as an open question
gated on v6a measurements.

### 3.1 The contract

The v6a invariant, mirroring GFS2:

> **While a node holds DLM lock L on resource R in mode M, the local
> kernel page cache and `xfs_buf` cache may contain anything for R.
> On lock release or demote (DLM unlock or downgrade), BEFORE the DLM
> release message is sent, the node MUST: (a) flush all dirty
> metadata for R (per-resource AIL drain + log force + FUA write),
> (b) invalidate all cached buffers/pages for R (so the next holder
> reads from disk).  On lock acquire (DLM grant) for a resource the
> node was not previously holding, no cached state for R is assumed
> to be valid.  Subsequent reads pull from disk.  Subsequent reads
> WHILE STILL HOLDING the lock are served from the page cache and
> xfs_buf cache normally.**

This is what v5's D6 says.  The only delta from current v5 is the
"subsequent reads while still holding the lock" clause, which is
implicit in the GFS2 model and explicit here because v5's current
implementation violates it via FUA-on-every-read.

### 3.2 The primitives

Five primitives in `mxfs_clayer/`, all kernel-internal:

#### `mxfs_invalidate_ag(ag_no)` — drop AG metadata

Called from the DLM lock-release path BEFORE the unlock message is
sent (release side) and from the DLM lock-grant path BEFORE the first
read is allowed (acquire side).  Walks the xfs_buf hash for all AG
metadata blocks and calls `xfs_buf_stale` + `xfs_buf_relse` on each:

- AGF, AGI, AGFL (3 blocks per AG)
- bnobt, cntbt, inobt, finobt, rmapbt, refcountbt root blocks
- All inode chunks in the AG (variable, ~64 blocks × N chunks)

Implementation reference: kernel XFS already has `xfs_buf_unpin`,
`xfs_buf_stale`, `xfs_buf_relse`.  No new low-level mechanism needed
— just an iteration over the AG's metadata block list.

The block list is enumerable from the AG header (AGF + AGI tell us
btree roots, btree blocks tell us inode chunks, etc.).  We don't have
to hash the whole xfs_buf cache — we can directly look up by known
block number.

#### `mxfs_invalidate_inode(ino)` — drop one inode

For inode-token release.  Drops kernel XFS's in-core `xfs_inode`
(via `xfs_iunlink_remove` or equivalent) and forces reload via
`xfs_iget` on next access.  Also calls `truncate_inode_pages_final`
on the inode's data mapping if PCACHE-class token is being released.

#### `mxfs_pagecache_inval_inode(ino)` — drop file pages

Wraps `truncate_inode_pages_final(VFS_I(ip)->i_mapping, 0)`.  Called
when PCACHE token is released to a peer.

#### `mxfs_ail_push_ag_sync(ag_no)` — per-AG AIL drain

Per v5 spec D8.  GFS2's `gfs2_ail_empty_gl(gl)` is the model.  Walks
the AIL, identifies items belonging to AG `ag_no` (xfs_buf_log_item
items have an `xfs_buf` whose `b_target`+`b_addr` resolves to an AG;
xfs_inode_log_item items have an inode whose `i_ino` decodes the AG),
and pushes only those.  Returns when AG-scoped items have all
completed.

This is the sess27 priority-0 fix listed in v5's spec §11.3.  It is
NOT new work for v6 — it's already on the v5 phase plan.  v6 inherits
it.

#### `mxfs_log_force_resource(R)` — per-resource log force

Equivalent of GFS2's `gfs2_log_flush(sdp, gl, ...)` scoped to one
glock.  v5 currently uses `xfs_log_force(SYNC)` which is global.
Per-resource log force is harder to bolt onto kernel XFS than
per-resource AIL drain, because the log itself isn't naturally
partitioned by resource.  Two options:

- **Easy path:** keep global `xfs_log_force(SYNC)` for now.  It's
  expensive but correct.  Cost is one log flush per cross-node lock
  movement, which is bounded by yield-quantum frequency.
- **Hard path:** introduce per-AG log records (a new transaction tag)
  and per-AG log-force.  Significant kernel-XFS modification.

We propose easy path for v6a.  Revisit if measurement shows global
log force is the bottleneck.

### 3.3 Where the primitives are called

Two callsites in the cluster layer:

**On lock release / demote** (`mxfs_clayer/release.c`, new):

```c
int mxfs_clayer_release_token(struct mxfs_token *t)
{
    int ret;

    /* §7.2 sequence from v5 spec, faithful */
    if (t->resource_kind == MXFS_TOKEN_AG) {
        ret = mxfs_ail_push_ag_sync(t->ag_no);
        if (ret) return ret;
    } else if (t->resource_kind == MXFS_TOKEN_INODE) {
        /* per-inode AIL — XFS inode log items */
        ret = mxfs_ail_push_inode_sync(t->ino);
        if (ret) return ret;
    }

    ret = xfs_log_force(t->mp, XFS_LOG_SYNC);
    if (ret) return ret;

    /* device-level cache flush for storage stacks where FUA-on-write
     * isn't sufficient (see v5 spec D7) */
    ret = blkdev_issue_flush(t->mp->m_ddev_targp->bt_bdev);
    if (ret) return ret;

    /* drop local cache so the next holder sees clean state.
     * NOTE: this is symmetric to the acquire-side invalidate.
     * Some prior FS designs only invalidate on one side; we do both
     * because (a) it's cheaper than getting it wrong, and (b) it
     * makes the invariant easier to reason about. */
    if (t->resource_kind == MXFS_TOKEN_AG)
        mxfs_invalidate_ag(t->ag_no);
    else if (t->resource_kind == MXFS_TOKEN_INODE)
        mxfs_invalidate_inode(t->ino);

    /* finally, the DLM call */
    return mxfs_dlm_unlock(t);
}
```

**On lock acquire from peer** (`mxfs_clayer/acquire.c`, new):

```c
int mxfs_clayer_acquire_token(struct mxfs_token *t)
{
    int ret;

    /* DLM grant first.  After this returns, we hold the lock; no
     * peer can modify the resource until we release. */
    ret = mxfs_dlm_lock(t);
    if (ret) return ret;

    /* If we held this token before (epoch unchanged) and never
     * released, the cache is still valid.  Skip invalidation. */
    if (t->epoch == t->cached_epoch && t->cached_epoch != 0)
        return 0;

    /* Otherwise: invalidate.  After this, kernel XFS's first read of
     * any block in the resource will go to disk via normal xfs_buf
     * read paths.  Subsequent reads while we hold the lock hit the
     * page cache normally. */
    if (t->resource_kind == MXFS_TOKEN_AG)
        mxfs_invalidate_ag(t->ag_no);
    else if (t->resource_kind == MXFS_TOKEN_INODE)
        mxfs_invalidate_inode(t->ino);

    t->cached_epoch = t->epoch;
    return 0;
}
```

### 3.4 What gets removed

The current `mxfs_buf_needs_fua_read` machinery in
`xfs/xfs_buf.c` is removed.  Specifically:

- `xfs_buf` no longer has a "needs FUA read" flag.
- Metadata reads use the normal kernel XFS xfs_buf paths
  (`xfs_buf_read`, `xfs_buf_get`, etc.) without modification.
- The hot path is unchanged — it goes through page cache and
  xfs_buf cache as native XFS does.

This is the entire reason cross-node metadata-heavy workloads will
get fast: most reads while holding a lock hit the page cache (no
SCSI), and the SCSI cost is paid once per cross-node lock movement
in the form of `mxfs_invalidate_*`, which scales with lock-movement
frequency, not with read frequency.

### 3.5 What stays unchanged

- The forked-XFS substrate (D2).
- The DLM (CAW + TCP, D4).
- The on-disk format (D14, D15, mkfs_mxfs).
- Per-AG AIL drain (D8) — already on v5 phase plan, just used here.
- Pinned-resource pattern (D9), yield quantum (D10), discard-on-
  membership (D11), eager-flush (D12), reload-after-relock (D13) —
  all still apply.  v6a is purely a cache-architecture change; the
  rest of the cluster contract is preserved.
- Multi-class tokens (D3) — orthogonal.  v6a can ship with
  single-class-per-inode tokens (current state) and multi-class can
  follow as planned.
- Layered architecture (D5) — orthogonal but converges with v6a
  because the new primitives all live in `mxfs_clayer/`.

### 3.6 Three measured hypotheses

Per the user's hypothesize→measure→develop→commit methodology, v6a is
structured as three falsifiable hypotheses with measurements that
either confirm or reject each.

#### Hypothesis H1 — "The fault is FUA-on-every-read, not FUA-on-acquire"

**Claim:** if we replace `mxfs_buf_needs_fua_read` with a one-shot
`mxfs_invalidate_ag` at lock acquire time, and let kernel xfs_buf
serve subsequent reads, the rsync cross-node bench drops from 9+ min
to under 30 s.

**Measurement:** rsync_bench.sh with 2-node parallel.  Baseline is
the sess30 9+ min number.  Pass condition: any value under 60 s
disconfirms the "design is fundamentally too slow" framing and
validates v6a as the path.

**Falsifying outcome:** if the bench is still >2 min after H1's
implementation, the bottleneck is somewhere else (per-acquire AG
invalidate cost, log force cost, lock-bouncing frequency) and v6a
alone is insufficient.

**Cost to test:** 1 session of implementation (the FUA-read-removal
+ AG-invalidate insertion is 200-400 lines), 1 session of measurement
+ instrumentation.  See §6.

#### Hypothesis H2 — "Lock-bounce frequency is the dominant remaining cost"

**Claim:** after H1, the next bottleneck will be the rate of
cross-node AG lock movements.  Each movement triggers
`mxfs_invalidate_ag` (drops xfs_buf entries) + first reads after
acquire (goes to disk).  If lock-bounce rate is, say, 10/s and AG
metadata is ~64 blocks × ~10 chunks × 4 KB ≈ 2.5 MB to re-read on
each acquire, that's 25 MB/s of redundant reads.  Tolerable.  If
lock-bounce rate is 100/s, that's 250 MB/s — unsustainable.

**Measurement:** during the 2-node rsync bench under v6a, instrument
lock-acquire/release counters per AG.  Compute bounce rate.  Compare
against bench wall-clock time.

**Decision rule:**
- bounce rate < 20/s and bench < 10 s: ship v6a.
- 20-50/s and bench 10-30 s: tune yield quantum (D10) up; re-measure.
- >50/s or bench >30 s: yield quantum saturation; consider v6b
  (LVB-state cache) or per-token-class refinement (D3) to reduce
  spurious bounces.

#### Hypothesis H3 — "OCFS2's LVB pattern would close any remaining gap"

**Claim:** if H2 reveals that stat-style reads (size, times, mode)
dominate the cross-node read traffic, exporting an LVB-equivalent
in the DLM grant message and seeding xfs_inode from it on acquire
will eliminate that traffic.

**Measurement:** profile reads in the `test_concurrent_write`
cross-verify phase.  If >50% of reads are stat-class (small blocks,
inode-only data), H3 is testable; if reads are dominated by data
extents or directory blocks, H3 doesn't help.

**Cost to test:** 1 session of profiling.  Implementation is a v6b
proposal not built yet.

The key methodological discipline: **DO NOT IMPLEMENT v6b BEFORE
MEASURING UNDER v6a.**  v6a is the smallest change that gets us into
the GFS2-amortized regime.  v6b is justified only if v6a measurement
shows specific residual costs that v6b addresses.

---

## 4. How v6a differs from current v5

| Aspect                   | v5 v0.3.128 (current)                              | v6a (proposed)                                    |
|--------------------------|----------------------------------------------------|---------------------------------------------------|
| Metadata read path       | `mxfs_buf_needs_fua_read` triggers FUA on every read marked stale | normal kernel xfs_buf path, page-cache amortized |
| Cache invalidation       | implicit via FUA-read (every read goes to disk)    | explicit `mxfs_invalidate_ag` once per acquire    |
| Cross-node read amort    | none — every read is SCSI                          | page-cache amortized (~4-16× per page)            |
| AIL drain                | `xfs_ail_push_all_sync` (whole-FS, deadlocks)      | `mxfs_ail_push_ag_sync` (per-AG, sess27 plan)     |
| Log force                | `xfs_log_force(SYNC)` (global)                     | unchanged — keep global for v6a                   |
| FUA on metadata write    | yes (D7), kept                                     | yes (D7), kept                                    |
| FUA on metadata read     | yes (D6 as-implemented)                            | **NO** — removed                                  |
| Lock state machine       | unchanged (single-class)                           | unchanged                                         |
| Forked XFS substrate     | yes (D2)                                            | yes — preserved                                   |
| DLM transports           | CAW + TCP (D4)                                      | unchanged                                         |
| Pinned resource (D9)     | spec'd, partial impl                                | unchanged — spec'd work continues                 |
| Yield quantum (D10)      | spec'd, partial impl                                | unchanged                                         |

What gets ripped out: the FUA-read mechanism in `xfs/xfs_buf.c` and
related glue (`mxfs_buf_needs_fua_read`, the SCSI READ(16) FUA path
in PAL).

What gets added: `mxfs_clayer/invalidate.c`, `mxfs_clayer/release.c`,
`mxfs_clayer/acquire.c`.  Roughly 600-1200 lines total.

What stays: everything else.

This is NOT a from-scratch rebuild.  It's a targeted replacement of
one mechanism (FUA-on-read) with a different mechanism (invalidate-
on-acquire) that the spec already calls for.

---

## 5. How v6a differs from mxfs.1

mxfs.1 is the architectural ancestor of "MXFS owns the cache and
manages invalidation explicitly."  v6a is the same idea applied to
kernel XFS's caches instead of mxfs.1's custom caches.  The
critical differences:

| Aspect                | mxfs.1                                              | v6a                                              |
|-----------------------|-----------------------------------------------------|--------------------------------------------------|
| Metadata cache        | Custom (libmxfs/{block,inode,dir}_cache.c)           | Kernel xfs_buf + page cache (forked from native XFS) |
| Read on miss          | Synchronous `submit_bio_wait` per block             | Async page cache fill via xfs_buf_read           |
| Read merging          | None (sess73 measured 0% merging)                   | Block layer merges, page cache readahead         |
| Read amortization     | 8-block readahead (sess73 added)                    | Native page cache (whole-page reads + readahead) |
| Single-node perf      | 4.3× XFS                                            | ~1.0-1.2× XFS (preserved from v5)                |
| Cross-node coherency  | Per-resource cache with explicit BAST handler       | Per-resource invalidate (mxfs_invalidate_*) at lock boundaries |
| Format-transition bug | YES (dir_cache.c, element-web rsync corrupts)       | NO (kernel XFS handles dir formats correctly)    |

The single most important difference is the read path.  mxfs.1's
direct-bio cliff (`pal_linux_kern.c::mxfs_pal_bdev_read` →
`submit_bio_wait` per buffer) is the source of its 4.3× overhead.
v6a inherits kernel XFS's read path, which uses page cache and gets
free amortization, readahead, and block-layer merging.

mxfs.1's lessons that v6a applies:
- Per-resource invalidation (not whole-cache).  Yes — `mxfs_invalidate_ag`
  is per-AG.
- BAST yield quantum to amortize lock movements.  Yes — D10, kept.
- Pinned resource for multi-step ops.  Yes — D9, kept.
- FUA writes on lock release.  Yes — D7, kept.
- Discard (not flush) on membership change.  Yes — D11, kept.

mxfs.1's lessons that v6a doesn't apply (because they're substrate-
specific to libmxfs caches):
- Hand-coded LRU + hash + dirty bit on every cache entry.  v6a uses
  kernel page cache LRU instead.
- Per-cache-type BAST handlers.  v6a's BAST handler is unified at
  the token-release level.
- Pre-flight format detection in `flush_dir_pinned`.  v6a delegates
  to kernel XFS dir code.

---

## 6. Implementation cost (sessions)

These are estimates with confidence ranges.  Sessions are
~2-4 hours of focused work in this project's experience.

### Phase 1 — Remove FUA-read, add basic invalidate

**1-2 sessions.**

- Remove `mxfs_buf_needs_fua_read` from `xfs/xfs_buf.c`.
- Remove the SCSI READ FUA path from PAL (or keep it as a debug
  module param for A/B comparison).
- Add `mxfs_invalidate_ag(ag_no)` and `mxfs_invalidate_inode(ino)`
  in `mxfs_clayer/invalidate.c`.  These are calls into existing
  kernel XFS primitives (`xfs_buf_stale`, `xfs_buf_relse`); the
  work is enumerating the AG metadata block list.
- Wire into existing DLM lock-grant and lock-release callbacks.

**Deliverable:** v0.4.0 (semantic version bump — this is a behavior
change at the architectural level).

**Risk:** Low.  We're removing a mechanism (FUA-read) and replacing
it with a related one (invalidate-on-acquire) that the spec already
prescribes.  Failure modes are well-understood (Mode A returns,
phantom-EX returns).

### Phase 2 — Per-AG AIL drain

**1-2 sessions.**

This is sess27's planned work, listed as v5 spec §11.3 phase 1.
v6 inherits it.  Work scope per spec: add `xfs_ail_push_ag_sync`
to `xfs/xfs_trans_ail.c`, modify `mxfs_dlm_ag_bast_work_fn` to use
it.  Already designed; just needs implementation.

### Phase 3 — Measure and validate H1, H2

**1-2 sessions.**

- rsync_bench.sh with 2-node parallel.
- `test_concurrent_write` from the cluster test suite.
- Lock-bounce-rate instrumentation per AG.
- Compare against sess30 baselines.
- If H1 confirmed (bench < 60 s): commit phase 1+2 as v6a stable.
- If H1 disconfirmed: re-evaluate.  Likely points back to the
  acquire-time invalidate cost being too high; tune (skip
  invalidate when epoch unchanged is the obvious knob).

**Deliverable:** measurement-grounded confidence that v6a is the
right architecture.

### Phase 4 (conditional on H2) — Tune yield quantum

**0-2 sessions.**

If lock-bounce rate is the residual cost, raise `MXFS_BAST_YIELD_QUANTUM`
from 32 to 128 or 256 for AG tokens.  Re-measure.  This is a knob
twist, not a redesign.

### Phase 5 (conditional on H3) — LVB-style stat cache

**3-5 sessions.**

ONLY IF H3's profiling shows stat-class reads dominate.  Bolt-on:

- New DLM grant message field carrying `xfs_dinode` snapshot
  (just core fields: size, di_nblocks, mtime, atime, ctime, mode,
  nlink, uid, gid).
- `mxfs_clayer/lvb_seed.c`: on lock acquire, if grant came with LVB,
  populate the in-core xfs_inode from those fields and skip the
  disk read.

This is v6b, not v6a.  Listed for completeness.

### Total v6a estimate: 4-8 sessions

| Phase                                  | Sessions | Confidence |
|----------------------------------------|----------|------------|
| 1: Remove FUA-read, add invalidate     | 1-2      | High       |
| 2: Per-AG AIL drain                    | 1-2      | High (already planned) |
| 3: Measure                             | 1-2      | High       |
| 4: Tune (if needed)                    | 0-2      | Medium     |
| **v6a total**                          | **3-8**  | **High**   |
| 5: LVB cache (v6b, conditional)        | 3-5      | Speculative |

For comparison: the v5 spec roadmap §11.3-11.6 (Phases 1-4) estimates
**5-12 sessions** for partial overlap with this work plus SCSI
root-cause investigation (Phase 3 D16).

### What we are NOT proposing

- We are **not** proposing to spend more sessions on D16
  (kernel SCSI passthrough non-persistence).  Sess30's measurement
  established that the underlying SCSI CAW persistence concern was
  mitigated by Path A (manual-bio submission, default `caw_path=1`).
  Residual CAW reliability issues at 15× scale appear to be elsewhere
  (LIO target config, scsi-mq dispatch — see sess30 conclusions).
  Those are server-side investigations, not architectural changes.
  v6a is independent.

- We are **not** proposing the multi-class token refactor (D3) as
  part of v6a.  D3 is large (5-8 sessions per spec §11.8) and
  orthogonal — v6a works fine with single-class-per-inode locks.
  D3 can come later as a perf optimization.

- We are **not** proposing an asymmetric metadata-server model.  That
  is a v7+ conversation.

---

## 7. Open questions and unknowns

This section is honest about what we don't know.  These should not
block proceeding; they should be resolved during implementation or
deferred consciously.

### 7.1 Is the FUA-on-write side (D7) sufficient on this hardware?

Spec D7 calls for FUA on metadata writes that cross release boundaries.
Sess30 instrumented this and found that on this hardware
(`/sys/block/sda/queue/fua=0`), LIO drops the FUA bit and the writes
land in the device write cache.  Sess30's `caw_flush=1` (post-CAS
`blkdev_issue_flush`) provided a marginal (4%) improvement.

**Question:** is `blkdev_issue_flush` post-write sufficient for
cross-node coherency on this hardware, or do we need additional
mechanisms (like an explicit FUA-read sentinel block on the
acquire side)?

**Plan:** measure during phase 3.  If 2-node bench passes correctness
under v6a + existing FUA-write + post-write flush, the answer is
"yes, sufficient."  If correctness fails (Mode A returns, peer reads
stale), we add the FUA-read sentinel.

### 7.2 What is the exact AG-metadata block list to invalidate?

`mxfs_invalidate_ag(ag_no)` must enumerate:
- AGF (block 0 in AG's superblock area)
- AGI (block 1)
- AGFL (block 2)
- bnobt root, cntbt root, inobt root, finobt root
  (read from AGF/AGI fields)
- All blocks in the bnobt, cntbt, inobt, finobt btrees
  (transitive walk)
- All inode chunks in the AG (enumerable via finobt)
- Possibly: rmapbt, refcountbt root and blocks (XFS v5 features)

**Question:** is a transitive walk feasible on lock acquire (it
involves reading the btree blocks, which is the very thing we're
trying to invalidate)?

**Plan:** check whether kernel XFS already has a primitive that
enumerates AG metadata for `xfs_repair`-like operations.  If not,
the simpler approach is to invalidate ALL xfs_buf entries whose
block-number falls within the AG's block range (start/end derivable
from `xfs_perag`).  This may invalidate some non-metadata blocks
unnecessarily; that's a cost we can afford because it's per-acquire,
not per-read.

### 7.3 How does `mxfs_invalidate_inode` interact with kernel XFS's
inode reclaim?

Kernel XFS has its own inode reclaim path (xfs_iget, xfs_irele,
`xfs_inode_clear_reclaim_tag`).  If we drop an in-core inode from
under XFS, we may leak `xfs_inode_log_item`s on the AIL or
desynchronize the inode hash.

**Plan:** read `xfs_iget`, `xfs_inode_free`, and `xfs_iflush_int`
during phase 1.  The cleanest hook may be to NOT drop the in-core
inode but to mark it stale in a way kernel XFS understands —
something like calling `xfs_iflush` to write any pending changes,
then `xfs_iunlink_remove` to unlink from the inode chunk's list.
Need to verify what's safe.

This is the riskiest part of v6a's implementation.  Mitigation: do
the AG-token case first (lower risk, since AG metadata is in xfs_buf
which has clean stale/relse semantics), measure, then tackle inode
case.

### 7.4 What about the page cache for file data (PCACHE token)?

For data reads/writes (file content, not metadata), the page cache
must also be coherent.  v5 spec D6 handles this via PCACHE token
class — when PCACHE is acquired from peer, call
`truncate_inode_pages_final`.

v6a inherits this.  No new design needed; just make sure
`mxfs_pagecache_inval_inode` is wired into the PCACHE-token-acquire
callback.

But: the rsync bench is mostly metadata-bound, so the data-path
coherency is unlikely to be the v6a bottleneck.  Measure first.

### 7.5 Will v6a produce a regression on single-node?

**Plan:** measure.  Single-node should be unaffected (no DLM
transitions, no invalidate calls fire).  If it regresses, we have a
bug.

### 7.6 Mode A (lost directory entries)

The persistent v5 bug.  v5 spec §11.4 phase 2 is dedicated to it
(D9 + D10).  v6a includes neither phase 2's deliverables nor
weakens them.

**Question:** does v6a's correct invalidate-on-acquire also close
Mode A directly, or is the pinned-resource + yield-quantum work
still needed?

**Hypothesis:** Mode A's root cause (per `sess27_lessons.md`,
`sess26_lessons.md`) is partially "stale cached state on the
acquiring node" (which v6a fixes) and partially "lock released
mid-op on the releasing node" (which only D9/D10 fix).  v6a closes
half of Mode A.  Phases 1+2 + D9/D10 close all of it.

**Plan:** during phase 3 measurement, run the Mode A reproducer.
If it passes, celebrate.  If it fails, D9/D10 work is still
required and v6a is necessary-but-not-sufficient.

### 7.7 What if v6a's measurement shows we're STILL slow?

There is a scenario where v6a's H1 is confirmed (bench under 60 s)
but it's still 10× XFS native.  At that point, the next architectural
move would be v6b (LVB stat cache) or a deeper change.  The proposal
explicitly does NOT pre-commit to that path; it gates on measurement.

The methodological discipline (the user's hypothesize-measure-
develop-commit cycle) is what protects us from over-engineering.

---

## 8. Recommendation

**Recommendation: implement v6a (described in §3).  4-8 sessions.
High confidence in the architectural direction.  Falsifiable via
H1 measurement at end of phase 3.**

Rationale:

- **It's the smallest change that addresses the measured problem.**
  v5 spec D6 already calls for invalidate-on-acquire; the implementation
  shipped FUA-on-every-read instead.  v6a is "do what the spec says."
- **It's the GFS2 model.**  GFS2 is a 20-year-old kernel-resident
  shared-block-device clustered FS that handles this exact workload
  on this exact substrate (kernel page cache for metadata, per-glock
  invalidation at DLM boundaries).  It is the proven design point.
- **The forked-XFS substrate is preserved.**  Single-node perf —
  the entire reason v5 exists and the entire reason mxfs.1 was
  abandoned — is not at risk.
- **The cluster correctness machinery (D7-D15) is preserved.**  We
  inherit, not lose, every cross-node correctness invariant the
  spec already commits to.
- **It's measurable.**  The 9+ minute rsync bench is a clear
  baseline; sub-60s on the same bench confirms v6a; sub-30s confirms
  it strongly; failure to improve falsifies it.
- **It's reversible.**  The FUA-read mechanism can stay behind a
  module param for the duration of phase 1-3, allowing direct A/B
  on the same hardware.

What we are NOT recommending:

- **Don't continue v5 with the current D6 implementation.**  The
  measured ceiling is the design hitting its limit.  Tweaking
  parameters (msleep values, caw_flush, etc.) won't move it.
- **Don't resurrect mxfs.1.**  Single-node corruption + 4.3×
  perf overhead.  It's reference material, not a target.
- **Don't pivot to an asymmetric metadata-server model.**  Major rewrite,
  separate question, v7+.
- **Don't pre-implement v6b (LVB-style stat cache) before measuring
  v6a.**  Discipline.

The single most important thing about this proposal is the
**measurement gate at phase 3.**  If v6a lands and the rsync bench
is still >2 minutes, we have a different problem than this proposal
diagnosed and the answer is to investigate further before adding
more mechanism.  No rationalizing past a failed measurement.

---

## 9. Appendix: hypothesis-driven checklist

For the implementation session(s):

- [ ] **H0 — Behavior preserved on single-node.** Run the rsync
      bench single-node before and after phase 1.  Pass: within
      10% of pre-v6a.  Fail: investigate.

- [ ] **H1 — Cross-node bench drops below 60 s.** rsync_bench.sh
      2-node parallel after phase 1+2.  Pass: under 60 s.
      Strong pass: under 30 s.  Fail: re-evaluate v6a.

- [ ] **H2 — Lock-bounce rate is sustainable.** Per-AG bounce
      counter during the bench.  Pass: <20/s with bench under 30 s.
      Marginal: 20-50/s — tune yield quantum (phase 4).
      Fail: >50/s with bench >30 s — escalate to v6b consideration.

- [ ] **H3 — Stat-class reads dominate residual.** Read-trace during
      `test_concurrent_write` cross-verify.  Threshold: >50% reads
      are stat-class.  If yes: v6b LVB cache is justified.
      If no: residual is data-extent or directory-block reads —
      different optimization.

- [ ] **Mode A reproducer passes.** Cluster test
      `concurrent_mkdir`/`concurrent_touch` from
      `tests/cluster/`.  Pass: 100% of expected entries on disk
      across 5 runs.  Fail: D9/D10 phase still required;
      v6a was insufficient on its own (still expected outcome).

- [ ] **AIL deadlock at 5×512 closed.** `mxfs_stress_v033.sh 5 512`.
      Pass: 15/15 iters.  This is sess27's open bug; phase 2's
      per-AG drain closes it.

The discipline: each box is checked only with a recorded measurement,
not a vibe.

---

## 10. References

Cited evidence and source documents.

**Local kernel sources:**
- `~/src/linux/fs/gfs2/glock.c` — GFS2 lock state machine
- `~/src/linux/fs/gfs2/glops.c` — per-glock-type ops (inode_go_inval,
  rgrp_go_inval, etc.)
- `~/src/linux/fs/gfs2/meta_io.c` — `gfs2_getbuf`, `gfs2_meta_read`
- `~/src/linux/fs/ocfs2/dlmglue.c` — OCFS2 DLM/cache integration,
  LVB pattern
- `~/src/linux/fs/xfs/xfs_buf.c` — kernel XFS xfs_buf (the cache
  v6a will use unmodified)

**MXFS internal:**
- `/src/mxfs/state.md` (sess30 closure) — the measurements that
  motivated this proposal
- `/src/mxfs/docs/mxfs-architecture-spec.md` — v5 spec, especially
  D6/D7 (§4) and §7 cache coherency contract
- `/src/mxfs/docs/priorart-research.md` — mxfs.1/2/3 synthesis

**MXFS prior versions:**
- `~/src/mxfs.1/handoff.md` (sess73) — perf cliff measurement,
  page-cache-based-metadata-I/O hypothesis
- `~/src/mxfs.1/FIX.md` — direct-bio + manual data-fork patch
  pattern
- `~/src/mxfs.1/libmxfs/{block,inode,dir}_cache.c` — what NOT to do
  for the read path

**Memory (sess26-30 lessons):**
- `~/.claude/projects/-src-mxfs/memory/sess30_lessons.md`
- `~/.claude/projects/-src-mxfs/memory/sess27_lessons.md`
- `~/.claude/projects/-src-mxfs/memory/sess26_lessons.md`
- `~/.claude/projects/-src-mxfs/memory/reference_mxfs1_sess74_results.md`
- `~/.claude/projects/-src-mxfs/memory/project_gfs2_coherency_pattern.md`

---

*End of v6 cache architecture proposal — sess31 v0.1*

---

## 11. CORRECTION (sess31 v0.2, after direct code reading)

After writing §1-§10, sess31 read the actual v5 v0.3.128 code paths
(`xfs/xfs_mxfs_dlm.c` lines 300-424, 2480-2716, 2810-2849; and
`pal/linux/xfs_buf.c` 1610-1640) and found the framing in §1.2 was
incomplete in a load-bearing way.  This section captures the
correction.  Sess32 should treat §11 as authoritative where it
conflicts with §1-§10.

### 11.1 What v5 actually does today

v5 v0.3.128 implements **both** invalidate-on-acquire **and**
FUA-on-every-read.  Both mechanisms are live; they layered over
many sessions.

**Invalidate-on-acquire** (already present, well-developed):

- AG token fresh-acquire path (`xfs_mxfs_dlm.c:2480-2716`): walks
  `pag->pag_bcache.bc_hash` via `rhashtable_walk_*`, identifies
  AG-metadata bufs (AGF, AGI, AGFL, bnobt, cntbt, inobt, finobt,
  rmapbt, refcountbt) plus inode cluster bufs, calls `xfs_buf_stale`,
  force-clears `XBF_DONE` (sess25 v0.3.99 fix — `xfs_buf_stale`
  alone doesn't clear DONE, so cached bufs were being reused without
  re-read).  Followed by `blkdev_issue_flush` on the bdev (v0.3.105
  sess25).  Logs counter via P22-INSTR walk-census.
- Inode-token release path (`xfs_mxfs_dlm.c:300-424` in
  `mxfs_dlm_reload_inode`): on inode lock release for directories
  in EXTENTS format, walks the dir's extent map, stales each dir
  block buf via `xfs_buf_stale + XBF_DONE-clear`, then
  `blkdev_issue_flush`.  Sess25 v0.3.84 fix.
- Peer-joined notify callback (`mxfs_dlm_peer_joined_flush`,
  `xfs_mxfs_dlm.c:3037+`): fires on cluster topology change.
- After staling, `xfs_perag_clear_initialised(pag)` (line 2729+) so
  next `xfs_alloc_read_agf` / `xfs_ialloc_read_agi` re-populate
  `pag->pagf_*` / `pag->pagi_*` from the freshly-read disk buffer
  (sess21 v0.3.21 fix).

**FUA-on-every-read** (added later, currently the dominant cost):

- `mxfs_buf_needs_fua_read` (`xfs_mxfs_dlm.c:2829-2849`) returns true
  for AG-metadata bufs, inode bufs (`xfs_inode_buf_ops`,
  `xfs_inode_buf_ra_ops`), and dir bufs (`xfs_dir3_data_buf_ops`,
  `xfs_dir3_block_buf_ops`, `xfs_dir3_leaf1_buf_ops`,
  `xfs_dir3_leafn_buf_ops`, `xfs_dir3_free_buf_ops`).
- `pal/linux/xfs_buf.c:1629-1636` checks this before submitting the
  bio — if true and multi-node, calls `mxfs_buf_read_fua(bp)` which
  issues a SCSI READ(16) with FUA bit set.
- Crucially, the comment at `xfs_buf.c:1618-1628` documents the
  v0.3.114b sess29 extension: FUA-read **also** covers READ_AHEAD,
  because without it "an inode/dir RA populates the local buf cache
  via plain bio (per-initiator iSCSI cache) with pre-modification
  content; subsequent xfs_buf_get returns the cached buf and never
  re-reads, so FUA never fires."

### 11.2 Why v5 has both (the hardware-stack story)

The `xfs_buf.c:1618-1628` comment is the load-bearing finding:
**`xfs_buf_stale` does NOT pierce the storage stack's own read
cache.**  Specifically:

1. v5 stales the in-memory `xfs_buf` via `xfs_buf_stale` and
   `XBF_DONE`-clear.
2. The next `xfs_buf_read` allocates new pages and submits a plain
   bio.
3. The bio goes through QEMU virtio-scsi → tcm_loop → LIO target.
4. **LIO's iblock backstore has its own per-initiator read cache**
   (or the underlying SCSI device's read cache below LIO does).  On
   commodity SSD with `/sys/block/sda/queue/fua=0`, that cache is
   not invalidated by upstream `blkdev_issue_flush`; it returns
   pre-modification content even though the disk has been modified.
5. To pierce it, the read must carry the FUA bit (or a SCSI
   `SYNCHRONIZE CACHE` must precede it).

This is **the same problem mxfs.1 hit on VMware multi-writer VMDKs**
(`docs/priorart-research.md` section 4, "VMware multi-writer I/O
coherency improvements").  mxfs.1's fix: FUA on every persistence-
critical write **and** SYNCHRONIZE CACHE before reads.  v5's
sess29 fix was substantively the same: FUA on every metadata read.

### 11.3 What this means for v6a

The §3 design as written ("remove FUA-read entirely, rely on
invalidate-on-acquire + blkdev_issue_flush") is **incomplete**.  On
this hardware (and on any SCSI stack with per-initiator read caching
below the kernel block layer), invalidate alone does not produce
fresh data.  A naive removal of FUA-read would re-introduce Mode A
on the dir-block buf path that sess29 closed.

The **corrected v6a design** is narrower:

> Keep invalidate-on-acquire (it already works).
>
> Narrow FUA-on-read from "every read while multi-node" to
> "first read of each invalidated buf since last invalidate."
> After the first FUA read, mark the buf as "freshness-confirmed";
> subsequent reads of the same buf while still holding the lock
> are plain bio — they hit the kernel page cache / xfs_buf cache
> without I/O.  On next invalidate (lock release/acquire), the
> freshness-confirmed bit is cleared.

This is a single new state bit on `xfs_buf` (or equivalent), checked
in `xfs_buf.c::xfs_buf_submit_bio` callsite at line 1629, set after
a successful FUA read, cleared by `xfs_buf_stale`.  Approximate
LOC: 50 lines.

This restores GFS2's amortization property — multiple metadata
reads of the same block while holding a lock cost ONE SCSI round
trip total, not N.  And it preserves the per-initiator-cache
piercing that v5's existing FUA-read mechanism provides.

### 11.4 Restated H1 (corrected)

The original H1 (proposal §3.6) said:

> "If we replace `mxfs_buf_needs_fua_read` with a one-shot
> `mxfs_invalidate_ag` at lock acquire time..."

This wording falsely implies v5 lacks invalidate-on-acquire.  It has
it.  The corrected H1 is:

> **H1 (v0.2):** If we narrow `mxfs_buf_needs_fua_read` from
> "always" to "only when the buf has not yet been re-read since its
> last stale event," subsequent metadata reads in the same lock-hold
> hit the kernel xfs_buf cache rather than triggering SCSI READ FUA,
> and the 2-node rsync bench drops from 9+ min to under 60 s
> (strong: under 30 s).

Same falsifying threshold, narrower mechanism.

### 11.5 Implementation cost (corrected)

Phase 1 cost drops significantly under the corrected design.  Most
of the v6a infrastructure already exists in v5.

| Phase                                         | Original estimate | Corrected estimate |
|-----------------------------------------------|-------------------|--------------------|
| 1: Narrow FUA to first-read-after-invalidate  | 1-2 sessions      | **0.5-1 session**  |
| 2: Per-AG AIL drain (D8)                      | 1-2 sessions      | unchanged          |
| 3: Measure H1                                 | 1-2 sessions      | unchanged          |
| 4: Tune yield quantum (if needed)             | 0-2 sessions      | unchanged          |
| **v6a total (corrected)**                     | **3-8**           | **2.5-7**          |

The phase 1 work is now: (a) add `b_freshness_confirmed` bit (or
analog on `xfs_buf->b_flags`); (b) check it in the FUA-read gate at
`pal/linux/xfs_buf.c:1629`; (c) set it after successful FUA read in
`mxfs_buf_read_fua`; (d) ensure all `xfs_buf_stale` callsites in
`xfs_mxfs_dlm.c` reset it (sess25 already pairs `xfs_buf_stale` with
`XBF_DONE`-clear, so the same callsites are the right place).

### 11.6 What the original §3 design got right

Most of the proposal still holds:

- The architectural model (GFS2-shaped invalidate-on-boundary +
  page-cache amortization within a hold) is the right target.
- Per-AG AIL drain (D8) is still needed independent of v6a.
- Pinned resource (D9), yield quantum (D10), discard-on-membership
  (D11) all still apply.
- The hypothesize → measure → develop → commit methodology is the
  right discipline.
- The recommendation (implement v6a, gate on H1 measurement) stands.
- The reference designs survey (§2) is unaffected.

What changed: the **implementation surface** is smaller and the
**residual risk** is lower than §3 suggested.  v5 already does most
of the work; v6a is a refinement, not a replacement.

### 11.7 Updated recommendation

**Implement v6a per §11.3 (narrow FUA, don't remove it).  2-3
sessions estimated.  Same H1 falsifying measurement.**

This is a smaller, lower-risk change than §3 originally framed.
It's also closer to "do the GFS2 thing" than "rewrite v5" — v5 is
already most of the way there, and the remaining gap is the
freshness-confirmed bit.

### 11.8 Methodology note

Sess31 wrote the §1-§10 design first, then read the actual v5 code
to verify claims.  The correction here is exactly what the
hypothesize → measure → **verify** → commit cycle is supposed to
catch: a design built on inferred behavior is less reliable than a
design built on measured behavior.  The user's framing is right.
Future sessions: read the code BEFORE writing the proposal, not
after.

### 11.9 Implementation sketch (verified feasible by code inspection)

After §11 was drafted, sess31 verified the freshness-bit approach is
implementable by inspecting the actual codebase.  Here are the exact
file:line touchpoints sess32 should modify.

**Step 1: Define flag.**  `xfs/xfs_buf.h:34` is `XBF_WRITE_FAIL (1u<<7)`;
bits 8-17, 19-20, 23-27 are unused (logrecovery=18, kmem=21, delwri=22,
livescan=28, incore=29, trylock=30).  Add:

```c
#define _XBF_FUA_FRESH   (1u << 19)  /* MXFS: re-read with FUA since
                                      * last stale; subsequent reads
                                      * skip FUA gate */
```

Add matching entry to `XFS_BUF_FLAGS` macro at `xfs_buf.h:53-69` so
trace events render the flag name.

**Step 2: Set flag on successful FUA read.**  `pal/linux/xfs_buf.c:1474-1480`
in `mxfs_buf_read_fua`, after `rc == 0`:

```c
if (rc == 0) {
    bp->b_flags |= _XBF_FUA_FRESH;       /* NEW */
    n = atomic64_inc_return(&mxfs_buf_fua_ok);
    ...
    xfs_buf_ioend(bp);
    return 0;
}
```

**Step 3: Clear flag in `xfs_buf_stale` itself.**  Cleaner than
modifying every callsite: `xfs_buf_stale` already clears
`_XBF_DELWRI_Q` at `pal/linux/xfs_buf.c:82`.  Extend that clear:

```c
void
xfs_buf_stale(struct xfs_buf *bp)
{
    ASSERT(xfs_buf_islocked(bp));

    bp->b_flags |= XBF_STALE;
    bp->b_flags &= ~(_XBF_DELWRI_Q | _XBF_FUA_FRESH);   /* MODIFIED */
    ...
}
```

This single change covers every staling path:

- All MXFS `xfs_mxfs_dlm.c` callsites (lines 318, 416, 710, 855, 2679).
- XFS-internal callsites in `xfs_trans_buf.c:144` (binval-from-trans)
  and `xfs_trans_buf.c:642` (trans buf invalidation).
- Future callsites that add `xfs_buf_stale` without explicit awareness
  of MXFS's flag.

Note: existing `bp->b_flags &= ~XBF_DONE` lines paired with
`xfs_buf_stale` in MXFS code (sess25 v0.3.99 fix) can stay as-is —
they're independent of this change, and the v0.3.99 comment about
`xfs_buf_stale` not clearing XBF_DONE remains accurate.  We're not
proposing to fold that into `xfs_buf_stale` because XBF_DONE has
broader semantics (it gates `xfs_buf_get` reuse) and changing its
clear-on-stale behavior could affect non-MXFS code paths.  The
freshness flag is MXFS-only, so MXFS's stale function is the right
place to manage it.

**Step 4: Gate FUA-read on freshness.**  `pal/linux/xfs_buf.c:1629-1636`:

```c
if ((bp->b_flags & XBF_READ) && !(bp->b_flags & XBF_WRITE) &&
    !(bp->b_flags & _XBF_FUA_FRESH) &&         /* NEW */
    bp->b_mount->m_mxfs_dlm &&
    !mxfs_v5_dlm_is_single_node(bp->b_mount->m_mxfs_dlm) &&
    mxfs_buf_needs_fua_read(bp)) {
    if (mxfs_buf_read_fua(bp) == 0)
        return;
    /* fall through to bio path on -EOPNOTSUPP / errors */
}
```

When the flag is set, the gate fails and submission falls through to
plain `xfs_buf_submit_bio` — i.e., normal kernel page cache and
xfs_buf cache paths.

**Total LOC delta:** ~10 lines added, **2 sites modified** (one
extra OR'd flag in `xfs_buf_stale`, one freshness check in the
FUA-read gate, one flag-set in `mxfs_buf_read_fua`, one flag bit
defined in `xfs_buf.h`).  Single flag, single gate, no new
infrastructure.  Existing MXFS callsites of `xfs_buf_stale` are
unchanged.

**Risk assessment:**

- **Correctness risk:** if `_XBF_FUA_FRESH` is set but the buf is
  used past a point where storage state changes (e.g., concurrent
  peer write that we somehow missed BAST for), we'd serve stale
  data.  Mitigation: every `xfs_buf_stale` clears the flag.  The
  invariant is: a buf with `_XBF_FUA_FRESH` set has been re-read
  AFTER its most recent invalidation, so its content matches disk
  as of that moment.  As long as every event that requires
  invalidation goes through `xfs_buf_stale` (which clears the flag),
  the invariant holds.
- **Verification:** during phase 3 measurement, instrument flag
  set/clear events.  Cross-check that every BAST received → all
  affected bufs end up with flag cleared → next read re-FUAs.
- **Fallback:** if the flag-clear path turns out to be incomplete
  (some invalidation site missed), set `module_param` knob
  `mxfs_buf_fua_persistent=1` to bypass the gate (force every read
  to FUA again).  A/B comparison against current v0.3.128 behavior.

**Confidence:** high.  The mechanism is small, the bit space is
available, every existing stale callsite is already paired with a
flag-clear that's the right insertion point, and the gate is one
extra check on a hot path that's already gated by `m_mxfs_dlm` +
`!is_single_node` (single-node and small clusters are unaffected).

*End of v6 cache architecture proposal — sess31 v0.2*
