# AG-Metadata Coherency Across DLM AG-Lock Grants (HISTORICAL DESIGN DRAFT — the SHIPPED design uses b_iodone instead, see status below)

> **Status (2026-04-25, end of session)**: The bug this doc addresses is FIXED in v0.2.5.
> The shipped fix uses a different hook point than this draft proposed — see
> `xfs/xfs_mxfs_dlm.md` "AG-Metadata Coherency" and `state.md` "What Was
> Accomplished — v0.2.5" for the implementation that actually went in.
>
> **Summary of the design evolution**:
>
> 1. **Draft v1 (this doc, body below)** — release-side flush via per-AG
>    delwri list + `xfs_log_force_seq` in `mxfs_ag_dlm_unlock`.  WRONG hook
>    point: unlock fires before `xfs_trans_commit`, so `li_seq=0` and the
>    buffer is pinned by the live trans.  Self-deadlocked on `b_sema`.
>
> 2. **Draft v2 (mentioned in "Revised hook-point options" below)** — defer
>    via `iop_committed` log-item callback.  ALSO WRONG: `iop_committed`
>    fires from `xlog_cil_ail_insert` at AIL-insert time (WAL durable) but
>    BEFORE the buffer's home-location bytes are on disk.  Peers would still
>    read stale bytes.
>
> 3. **Shipped v0.2.5** — defer via `bp->b_iodone` per-buffer
>    write-completion callback, which fires from `__xfs_buf_ioend` AFTER
>    on-disk writeback.  This is the correct hook.  Combined with
>    acquire-side rhashtable walk that stales clean AG-meta buffers (filter:
>    no `b_log_item`, no `_XBF_DELWRI_Q`), the regular-file dd reproducer
>    passes with no corruption / shutdown.
>
> The bidirectional principle (release-side defer + acquire-side invalidate)
> from this draft is correct and survived in the final implementation.  Only
> the specific hook mechanism changed.


## Problem

After v0.2.4, MXFS passes mkdir-only stress (20/20 2-node) but fails
under any workload that frees extents — regular-file `dd` write,
truncate, unlink, inodegc — with:

```
XFS (sda): Internal error ltbno + ltlen > bno at line 2105 of file
/src/mxfs/xfs/libxfs/xfs_alloc.c.  Caller xfs_free_ag_extent+0x3de
```

Followed by `xfs_force_shutdown(SHUTDOWN_CORRUPT_INCORE)`.

Root cause: AGF / AGI / AGFL / free-space-btree / inobt / finobt /
rmapbt / refcountbt buffers are not synchronized across DLM AG-lock
grants. The local `xfs_buf` cache holds a stale view of AG metadata
after a peer has modified it under its own AG-lock hold. The per-AG
delwri added in v0.2.2 covers cluster buffers (newly-allocated inode
clusters), not AG-metadata buffers.

mkdir doesn't trip this because mkdir only allocates inodes;
`xfs_free_ag_extent` is the canary, exercised by extent-free paths.

## Prior Art

### mxfs.1 (32-node battle-tested, custom block cache)

Bidirectional, WAL-ordered:

- **Acquire** (`libmxfs/alloc.c:lock_ag` line 270+): drop entire AG
  range from custom `bcache` via `mxfs_block_cache_invalidate_range`.
- **Release** (`flush_cached_ag` line 187+): journal-commit →
  journal-flush (SYNCHRONIZE CACHE) → bcache-flush AG-range (no sync) →
  `bdev_flush` → `dlm_unlock`.
- **Dirty tracking**: implicit via compound journal txn opened on
  acquire + closed on release. Pre-images captured by explicit calls
  inside btree-modifying code, with per-buffer `logged_txn_id`
  idempotency guard. No per-buffer dirty list.

mxfs.1 had its own bcache with a range-invalidate API. v5 uses kernel
`xfs_buf` cache, which has only `xfs_buf_incore` (exact lookup) and no
range-invalidate.

### OCFS2 (production shared-disk)

Three-layer model:

1. **Release-side**: blocks DLM downconvert until journal checkpoint
   advances past the metadata's `ci_last_trans` (`ocfs2_ci_checkpointed`
   in `dlmglue.c`). Bounded — waits for a specific transaction ID, not
   "all activity".
2. **LVB**: per-resource generation number; cached buffer is trusted
   without disk read if LVB generation matches local cache.
3. **Acquire-side**: unconditional `ocfs2_metadata_cache_purge` of the
   inode's metadata extent map (`ocfs2_inode_lock_update`).

OCFS2's release pattern is the key insight for v5: **wait on a specific
log position**, not on the entire AIL — that's what makes it bounded
under concurrent activity.

### GFS2 (per-glock release/invalidate contract)

GFS2's *transport* is not a model for MXFS — it runs the kernel TCP DLM and does
not aim at clusters this size; the reasoning for CAW is in `docs/dlm-protocol.md`.
Its *coherency contract* is a separate axis, and on that axis it is the best
reference available: twenty years of hardening, with both halves of the contract
in one file, `~/src/linux/fs/gfs2/glops.c`.

`inode_go_sync` (glops.c ~303) runs BEFORE the glock is released or demoted:

1. `inode_dio_wait` — drain direct I/O
2. `gfs2_log_flush(... NORMAL ...)` — flush the journal
3. `filemap_fdatawrite(metamapping)` — write metadata pages
4. `filemap_fdatawrite` + `fdatawait` — write and wait data pages (regular files)
5. `gfs2_inode_metasync(gl)` — sync metadata buffers
6. `gfs2_ail_empty_gl(gl)` — **per-glock** AIL drain

`inode_go_inval` (glops.c ~358) runs on demote, once the peer owns the glock:

1. `truncate_inode_pages(mapping, 0)` — drop every cached page
2. `set_bit(GLF_INSTANTIATE_NEEDED)` — force reload from disk
3. `gfs2_dir_hash_inval(ip)` — drop the directory hash cache
4. `forget_all_cached_acls` / security-context invalidate

Two MXFS gaps this reference exposes, both of which were found the hard way
first:

**AIL granularity.** `mxfs_dlm_ag_bast_work_fn` drains with
`xfs_ail_push_all_sync` — the whole AIL. GFS2 drains per glock. The whole-AIL
primitive deadlocks under stress because items belonging to *other* locks block
the drain; that is the sess27 5×512MB deadlock. The answer is a per-AG drain
(`xfs_ail_push_ag_sync(ag)`, filtering by AG/inode), not a bounded timeout —
sess27 proved a bounded timeout breaks correctness, and left an unused
`xfs_ail_push_all_sync_timed` stub in `xfs_trans_ail.c` that is the wrong shape.

**Cache invalidation on demote.** "single→multi transition leaves a stale
`i_dlm_mode` + `pag_dlm_cached`" is the mirror image of GFS2's
`GLF_INSTANTIATE_NEEDED` machinery. GFS2 throws the cache away on demote and
forces a reload on the next acquire; MXFS tries to track validity through
`i_dlm_mode`, and that tracking is where the bugs live. Throw-and-reload is the
simpler and safer shape.

## Why The Previous Fix Attempt Failed (this session)

Tried "stale AGF/AGI/AGFL on fresh DLM AG-acquire" alone — `xfs_buf_incore`
+ `xfs_buf_stale` of the three AG-header buffers in
`mxfs_ag_dlm_lock`'s fresh-acquire path. Result: corruption *faster* (T1
shutdown 70s vs 80s baseline) plus mid-test EIO.

Diagnosis: AG-headers were dirty in our cache because they had not been
flushed during the prior `mxfs_ag_dlm_unlock`. Staling discarded our own
un-persisted writes. **The fix is bidirectional and inseparable**:
release-side flush + acquire-side invalidate, atomically with respect to
DLM lock state.

## Design

### What does NOT work (must not repeat)

`xfs_log_force(mp, XFS_LOG_SYNC) + xfs_ail_push_all_sync(mp->m_ail)` in
`mxfs_ag_dlm_unlock`:

- `xfs_log_force(SYNC)` waits for the *entire* in-core log to flush.
- `xfs_ail_push_all_sync` (xfs_trans_ail.c:711) waits while
  `xfs_ail_max(ailp) != NULL` — i.e., until the **entire AIL** is empty.

Both are unbounded under concurrent allocation: peer allocations keep
adding to log/AIL faster than we can drain → livelock.

### What does work — bounded primitives

**Release-side**:

1. `xfs_log_force_seq(mp, max_csn, XFS_LOG_SYNC, &forced)` — bounded by
   the CIL checkpoint sequence number `max_csn` of buffers we logged
   during *this* AG-hold. Concurrent allocators publishing newer CSNs
   don't extend our wait.
2. `xfs_buf_delwri_submit(&drain)` — writes a *fixed snapshot* of
   buffers we explicitly enqueued. New buffers added by peers after the
   splice don't grow the wait.
3. `blkdev_issue_flush(mp->m_ddev_targp->bt_bdev)`.
4. `mxfs_v5_dlm_ag_unlock`.

**Acquire-side**:

`mxfs_dlm_invalidate_ag_range(mp, agno)` — walk
`mp->m_ddev_targp->bt_cache` rhashtable, stale every buffer whose
`bm_bn` is in `[agno*sb_agblocks, (agno+1)*sb_agblocks)` (in BBSIZE).

Range walk (not list-replay) is required because the per-AG dirty list
only tracks buffers *we* logged. Buffers we read but did not modify
(e.g. tree blocks we walked during `xfs_alloc_vextent`) must also be
invalidated, since a peer may have changed them.

### Per-AG dirty AG-metadata buffer list

Parallel to the existing `pag_mxfs_alloc_buflist` (cluster buffers):

```c
/* xfs_ag.h, struct xfs_perag, kernel-only block */
struct mutex        pag_mxfs_agmeta_buflist_lock;
struct list_head    pag_mxfs_agmeta_buflist;  /* delwri list */
xfs_csn_t           pag_mxfs_agmeta_max_csn;  /* max CIL seq */
```

### Hook: `xfs_trans_log_buf`

```c
void xfs_trans_log_buf(tp, bp, first, last)
{
    ...
    xfs_buf_item_log(bip, first, last);

    /* MXFS multi-node: track AG-metadata buffer for sync release */
    if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)
        && mxfs_buf_is_ag_metadata(bp))
        mxfs_ag_metadata_track(tp, bp);
}
```

`mxfs_buf_is_ag_metadata` discriminates by `bp->b_ops`:
`xfs_agf_buf_ops`, `xfs_agi_buf_ops`, `xfs_agfl_buf_ops`,
`xfs_bnobt_buf_ops`, `xfs_cntbt_buf_ops`, `xfs_inobt_buf_ops`,
`xfs_finobt_buf_ops`, `xfs_rmapbt_buf_ops`, `xfs_refcountbt_buf_ops`.

`mxfs_ag_metadata_track`:
- Determines AG from `bp->b_maps[0].bm_bn / sb_agblocks_in_BBSIZE`.
- Acquires `pag_mxfs_agmeta_buflist_lock`.
- Calls `xfs_buf_delwri_queue(bp, &pag->pag_mxfs_agmeta_buflist)`
  (idempotent — uses `_XBF_DELWRI_Q` flag).
- Updates `pag_mxfs_agmeta_max_csn = max(current, bip->bli_item.li_seq)`.

### Release-side flush

In `mxfs_ag_dlm_unlock`, in the `pag_dlm_holders == 0` branch (right
alongside the existing alloc_buflist drain):

```c
LIST_HEAD(meta_drain);
xfs_csn_t meta_csn = 0;

mutex_lock(&pag->pag_mxfs_agmeta_buflist_lock);
list_splice_init(&pag->pag_mxfs_agmeta_buflist, &meta_drain);
meta_csn = pag->pag_mxfs_agmeta_max_csn;
pag->pag_mxfs_agmeta_max_csn = 0;
mutex_unlock(&pag->pag_mxfs_agmeta_buflist_lock);

/* (after pag_dlm_lock released) */

if (!list_empty(&meta_drain)) {
    int forced = 0;
    if (meta_csn)
        xfs_log_force_seq(mp, meta_csn, XFS_LOG_SYNC, &forced);
    xfs_buf_delwri_submit(&meta_drain);
    blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
}
```

Order matters: log first (WAL durable), then metadata buffers, then
device cache flush. Same WAL-then-data ordering as mxfs.1.

### Acquire-side invalidate

`mxfs_dlm_invalidate_ag_range(mp, agno)` called in `mxfs_ag_dlm_lock`'s
fresh-acquire branch (after `mxfs_v5_dlm_ag_lock` succeeds, before
returning):

```c
void mxfs_dlm_invalidate_ag_range(struct xfs_mount *mp,
                                  xfs_agnumber_t agno)
{
    struct xfs_buftarg *btp = mp->m_ddev_targp;
    xfs_daddr_t start = (xfs_daddr_t)agno * mp->m_sb.sb_agblocks
                        * (mp->m_sb.sb_blocksize >> BBSHIFT);
    xfs_daddr_t end   = start + mp->m_sb.sb_agblocks
                        * (mp->m_sb.sb_blocksize >> BBSHIFT);

    /* Walk btp->bt_cache (rhashtable). For each buffer:
     *   if (bp->b_maps[0].bm_bn >= start &&
     *       bp->b_maps[0].bm_bn < end)
     *       xfs_buf_stale(bp);
     */
}
```

Key constraint: `xfs_buf_stale` of a buffer that's currently held by
another transaction is safe — it sets `XBF_STALE`; the next
`xfs_buf_get`/`xfs_buf_read` will skip the cache and re-read from disk.

### Why this is bounded under concurrent allocation

- `xfs_log_force_seq(meta_csn)` waits only until that specific CIL
  checkpoint is durable. Peers logging newer items get newer CSNs;
  those don't block us.
- `xfs_buf_delwri_submit(&meta_drain)` writes only the buffers we
  spliced. Peers logging more AG-metadata after our splice are queued
  on `pag_mxfs_agmeta_buflist` (or a peer's perag) and don't enter our
  drain.
- Same bounded-snapshot pattern as the existing alloc_buflist drain.

This is the OCFS2 invariant translated to XFS: wait on a specific
position, never on a global state.

## Failure modes considered

1. **Buffer pinned by uncommitted txn**: `xfs_log_force_seq(SYNC)`
   forces the CIL to commit any pinned items. After the force returns,
   the items are unpinned. Then `xfs_buf_delwri_submit` succeeds.
2. **Buffer concurrently being written by AIL**: `_XBF_DELWRI_Q` and
   `b_sema` serialize. Worst case: AIL writes first, our delwri
   becomes a no-op (XBF_DONE already set).
3. **Acquire-side: peer holds the lock**: by definition, fresh acquire
   means peer released → its `mxfs_ag_dlm_unlock` already flushed and
   `blkdev_issue_flush`'d. Our subsequent stale-then-read sees fresh
   bytes.
4. **Cache buffer in use by parallel transaction on our node**: we
   only fresh-acquire when `pag_dlm_holders == 0` (also under
   `pag_dlm_lock`), so no local readers can be mid-AG-metadata-read.
5. **Single-node mode**: hooks no-op via `mxfs_v5_dlm_is_single_node`.

## What this draft got wrong (2026-04-25)

Discovered after deploy + dd hang.  `mxfs_ag_dlm_unlock` is called by
allocation paths (xfs_alloc.c:3579, 3588, 3681, 4049, 4075, 4080;
xfs_ialloc.c:1888, 1894) **before the modifying transaction commits**.
At that point:

- `bp->b_log_item->bli_item.li_seq == 0` — the CIL hasn't seen the trans
  yet, so `xfs_log_force_seq(0, SYNC)` is a no-op and we have no LSN to
  bound on.
- The buffer is pinned by the live trans via `xfs_buf_log_item.bli_refcount`
  and held under `b_sema`.  `xfs_buf_delwri_submit` blocks on `b_sema`
  until trans commit releases it — caller is the same thread, so this
  is a self-deadlock.
- Even if we bypassed the lock, writing the buffer here violates WAL
  ordering: changes are in CIL but not yet in the on-disk log.

Cluster buffers (`pag_mxfs_alloc_buflist`) escape this trap because
they are *ordered buffers*, not log items — they have their own ref
via `xfs_buf_hold` and are not pinned by trans commit.  AG-metadata
buffers are different and the existing alloc-buflist pattern doesn't
generalise to them.

## Revised hook-point options

1. **Move `mxfs_ag_dlm_unlock` to after `xfs_trans_commit`** at every
   call site.  Many call sites are inside `xfs_defer_finish` (e.g.
   `xfs_extent_free_finish_item` calls `__xfs_free_extent` which calls
   unlock at line 4075) where the trans is *rolled* (commit + new trans)
   between operations rather than committed at the operation site.
   Roll happens in `xfs_defer_finish_one` after each item.  Would need
   either a per-defer-op "pending unlock" stash drained after the roll,
   or a deeper restructure.

2. **Defer the flush+release to a transaction-commit callback.**  XFS
   already has `xfs_log_item.li_ops->iop_committed` (called when AIL
   delete fires after on-disk commit).  Attach a custom log item that
   fires when the AGF/AGI/AGFL/btree buffers complete writeback, then
   does the DLM release.  Local `pag_dlm_holders` count drops to 0
   immediately (so local code can re-acquire), but the actual remote
   DLM release waits for AIL writeback.  Local re-acquires hit the
   cached EX grant via the DLM layer.

3. **OCFS2-style downconvert-blocking** (`ocfs2_ci_checkpointed`).
   On `mxfs_ag_dlm_unlock`, capture the *current* CIL seq (or read
   one cached on the perag updated at every `xfs_trans_log_buf` of an
   AG-metadata buffer).  Do NOT release the DLM lock yet.  When the
   DLM layer would release (immediate release in current design, or
   on BAST in option 2's design), wait for AIL min lsn ≥ captured seq
   before allowing the release.  Bounded — concurrent allocators on
   other AGs publish their own seqs which don't extend our wait.

Option 2 (commit callback) is closest to the OCFS2 model and avoids
touching every call site.  Pre-implementation it requires:

- Confirming `iop_committed` fires *after* the buffer's data is on disk
  (it fires after AIL delete, which fires after `xfs_buf_iodone` on
  successful writeback — yes, on-disk).
- Identifying when to attach our log item.  Probably at
  `xfs_trans_log_buf` time (same hook this draft used), but instead of
  a delwri queue, attach a tiny log item that triggers DLM release
  when its `iop_committed` fires.
- Coordinating multiple holds of the same AG: only the LAST holder's
  trans-commit triggers DLM release, but the on-disk commit ordering
  is what matters, not the local hold count.

## The fence re-architecture: what it fixed, and the gap it relocated

### Provenance correction (user, 2026-06-07)
The cache_coherency **re-architecture** is the three-invariant FENCE design recorded in
`docs/history/compiled-bnobt-inode-double-alloc-ccloop.md`. Its body attributes it to "GPT-5.5" — **that attribution is WRONG**.
The user produced it yesterday (2026-06-06) as a **Grok + Gemini + Claude** collaboration,
driven by the self-contained problem statement in `/src/mxfs/CACHE_COHERENCY_ISSUE.md`
(written for external architectural review). It is SEPARATE from `NEWARCH.md` (which only
re-architects the *notification transport* — TCP invalidation mesh — and whose Phase-0 gate
already returned Outcome 3 "cannot pass even fully synchronous", deferring the mesh).

### The design (three fence invariants)
- **Inv 1** — DLM EX release/demote = a real **checkpoint fence**: every buffer the lock
  protected must have reached the shared target AND be clean / non-pinned / **not left as an
  AIL obligation** before unlock. No timeout/best-effort; writeback fail → shutdown.
- **Inv 2** — slow-path EX acquire = an **invalidation fence**: bump gen, mark cached bufs
  stale, re-read from target before first use. Never write a stale buf on acquire.
- **Inv 3** — the "keep stale & continue" (DIR-STALE-SKIP) branch becomes **FATAL**.
- Footnote in the design (load-bearing): *"the same fence design applies to AG locks
  (AGF/AGI/AGFL/bnobt bufs)."*

### Did it work? Partially — and it RELOCATED the bug (the key finding)
1. Implemented for **dir/inode locks** across sess88→99→103→107 → **worked**: killed the dir
   data-coherency bugs (rename_visibility / unlink_visibility / cross_visibility now pass).
2. **Never applied to the AG/allocation locks.** That omission IS the **bnobt double-free**
   (durable: on-disk inode owns a block the bnobt lists free; P47 DISK-LIVE-same-gen / P81
   disk_claims_freed=1). The last ~dozen sessions (incl. ccloop sess19–22) band-aided it with
   WRITE-SIDE interlocks at xfs_buf_submit (P122 split-revert; P124 alloc-revert, proven this
   session) instead of fixing the lock-handoff layer. P124 = a last-instant degenerate Inv 1.
3. Applying Inv 1's **synchronous drain-before-release rigorously EXPOSED the §6 structural
   lock-inversion** → the symptom class shifted from DATA corruption to a **LIVENESS wedge**
   (sess109–113): drain runs in the BAST kworker but must flush buffers owned by XFS's own
   b_sema/ILOCK/xfsaild that the kworker can't reach → root-inode (ino=128) cluster buffer left
   locked + in-AIL + off-list → drain spins forever → peer EX times out → shutdown.
   (sess113 named the leaked-lock root via b_lock_ip tracking: merge_dirs forced-FU path.)

### What "get past this" actually means (CACHE_COHERENCY_ISSUE.md §10)
The recurring wall is the §6 lock-inversion. The architected answer is to change **WHERE the
release-path drain runs**, GFS2-glock-style (`inode_go_sync`/`inode_go_inval`):
either make the **DLM strictly outermost** (acquire DLM before any XFS buffer/ILOCK so the BAST
path never waits on a buffer a blocked local thread owns), OR **move the drain out of the BAST
kworker** into the context that already owns ILOCK. PLUS apply the fence to **AG locks** (fix the
frozen `pag_dlm_meta_gen` so Inv-2 acquire-invalidation actually fires for AG-meta — the
sess19b shared-epoch finding; AG analog of the dir SEQLOCK epoch `docs/history/compiled-cc-dir-block-lost-update.md`).

### The standing directive
Write-side interlocks (P122/P124) are STOPGAPS that relocate the failure, not the fix. Don't
drift back into them. The real work is the GFS2-style drain relocation + AG-lock fence.
Related campaign history: `docs/history/compiled-cc-dir-block-lost-update.md`,
`docs/history/compiled-cc-create-rename-publish-visibility.md`,
`docs/history/compiled-cc-drain-ail-push-wedge.md`,
`docs/history/compiled-bnobt-inode-double-alloc-ccloop.md`.

## Test (still applies once hook point is fixed)

Reproducer (state.md):

```bash
T1: dd 1GB → rm → drop_caches
T2:        drop_caches
T1, T2: concurrent dd 1GB
T1: rm both
```

Expected v0.2.5: no `Internal error ltbno + ltlen > bno`, no
`SHUTDOWN_CORRUPT_INCORE`, both rm succeed.

Mkdir regression (`b18aem44o` cohort): expected 20/20 — guard hooks for
this fix do not affect the mkdir path materially (mkdir does log
AGI/AGF, but the additional delwri-queue + log-force are fast paths
that don't change correctness).

## 2026-08-22/23 (sess398-402): the un-tenured AGI writer — D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399

The shipped design (drain at release, stale-and-reread at acquire, read-hook
in-AIL protect) rests on one precondition: **every modification of an AG-meta
buffer happens under this node's AG-DLM tenure**, so the release drain sees it
and the read hook's in-AIL protect ("in-AIL AG-meta is this-node-ahead of the
peer") is true.  sess399 found two writers that broke it:

- `xfs_dir_add_child()` — the `linkat(AT_EMPTY_PATH)` completion of an
  O_TMPFILE (xfs_dir2.c ~1578) — and the rename-whiteout path
  (xfs_dir2.c ~2048) both called `xfs_iunlink_remove()` with **no
  `mxfs_ag_dlm_lock`**.  The REMOVE logged the AGI with no drain owed; its BLI
  stayed in the AIL across a peer's tenure; our next acquire preserved the
  stale in-AIL AGI; the first RMW against freshly re-read inobt/finobt leaves
  produced `agi_freecount` ±1 and the release published it.  A +1 ghost blocks
  every create in a full AG (`xfs_dialloc_ag_finobt_near` "i != 1 && j != 1",
  -EFSCORRUPTED); a -1 ghost trips `P-DIFREE-CORRUPT` shutdown.  Repro without
  an injector: `tests/agifc_churn_experiment.sh <label> pernode 0 200 32`
  (17 s).  Platter decode: `tools/mxfs_agi_dump.py`.

Fixes (0.23.11-0.23.13, sess400), one by instrument cycle:
1. AG-DLM bracket around `xfs_iunlink_remove` in both callers, same shape as
   `xfs_iunlink` (lock before `xfs_read_agi`; error -> unlock; success ->
   `mxfs_ag_dlm_unlock_deferred(tp)`).
2. `xfs_read_agi` rebuilds `pagi_freecount/pagi_count` whenever `AGI_INIT` is
   clear (a fresh acquire clears it; only `xfs_ialloc_read_agi` used to
   rebuild), so every AGI reader's summary matches the buffer it holds.
3. `xfs_link` pre-acquires the source inode's AG when `nlink==0`
   (`mxfs_trans_preacquire_inode_ags`, the pattern `xfs_rename` already used
   for the whiteout) so the fix-1 bracket cannot block holding both ILOCKs
   against a peer-held AG.

Always-on audits kept as the standing alarms: `P-AGIFC-MISMATCH` /
`P-AGIFC-RELEASE` (AGI count vs leaf totals at entry/release),
`P-AGIFC-MOD` ledger, `P-IUNL-RM-NOTENURE` (an AGI bucket remove with
holders==0 — the precondition violation itself), and the layer-2 read-hook
alarm `P-AGMETA-PRIORTENURE-UNDESTAGED-INAIL` (a prior-tenure AG-meta buffer
found in-AIL, clean, unpinned and undestaged at acquire = the sess399 state,
now an invariant violation).  Oracle note: `chk_mxfs` on a LIVE LUN is invalid
for a currently-held AG (inobt/finobt buffers can land up to 15 s apart at the
same LSN); quiesce with `AGIFC_UMOUNT=1` before reading.

Lock-order note (GPT-flagged, documented, not changed): the bracket takes
AG(inode)->AG(dir), the edge `xfs_create` already takes; `xfs_remove` takes
AG(dir)->AG(inode).  MXFS has no global ascending-agno policy; the cross edge
is mitigated by trylock/hold-nothing-while-blocking, a separate pre-existing
hazard.

## 2026-08-28 (sess432): the single-node false-fresh discard — D-0353 (0.39.11 / 0.39.12)

**Measured defect.** A node that mounts the LUN alone (`dlm_caw: single_node = true`)
double-allocated the inode of the directory it had just created, on the first file
create inside it (`Allocated a known in-use inode`, `ino == parent` at
`xfs_ialloc.c` dialloc verify → forced shutdown).  `tests/lone_mount_create.sh`
reproduces it in 9 s on 0.39.9.  Chain, all instrumented:

1. `dlm/dlm_caw.c caw_lock()` single-node fast path grants in memory and returned the
   UNSET/epoch-0 grant result (no slot image, nothing to mint from).
2. `xfs_mxfs_dlm.c` published `pag_mxfs_grant_epoch = 0` (P243-AGAUTH-UNBOUND).
3. The sess291 guard (`pag_dlm_cached && is_caw && epoch == 0` → drop the hint) fired
   on EVERY re-acquire → fresh attested acquire with the lineage still open
   (P130-FALSE-FRESH).
4. `mxfs_dlm_invalidate_ag_meta` (fresh-acquire caller) staled the AGI/inobt/finobt
   buffers while they were PINNED with the mkdir's CIL-resident update
   (P131-INVAL-DISCARD pin=1 ×3 — the sess3 probe that was log-only).
5. The platter re-read showed the inode still free → allocated again.

**Fixes (design-consult ruling `docs/rulings/single-node-false-fresh-discard.md`).**

- 0.39.11 — provenance: `MXFS_GAUTH_SINGLE_NODE` (`include/mxfs/mxfs_dlm.h`), filled by
  the single-node fast path; XFS records it as `pag->pag_mxfs_grant_single` beside the
  (zero) epoch.  The P243 guard keeps a SINGLE_NODE hint only while
  `mxfs_v5_dlm_is_single_node()` is still true; once the DLM has left single-node
  mode the hint is dropped (`src=single-era-ended-*`) and the acquire attests on disk.
  The join barrier's administrative lineage reset clears the flag with the epoch.
  Verified: `tests/lone_mount_create.sh s432c test1` PASS (zero P243/P130/P131).
- 0.39.12 — fail-closed invalidation (the loss mechanism, independent of the trigger):
  - `mxfs_agmeta_buf_unlanded(bp)`: pinned (CIL window) | bli DIRTY | bli IN_AIL |
    `_XBF_DELWRI_Q`.
  - Fresh-acquire caller (`ag_preserved == NULL`): a dry PREFLIGHT walk runs first; any
    un-landed AG-meta buffer → `P131-INVAL-REFUSED` + `xfs_force_shutdown`, NOTHING
    staled (all-or-nothing, no partial view, no home writes issued — the ruling forbids a
    log-force/AIL-push here because a genuine fresh grant may follow a peer's writes).
  - Census callers (join barrier, recovery barrier): the locked branch now RETAINS an
    un-landed buffer (`P47-INVAL-SKIP-INAIL ... locked`) like the other two branches,
    so the caller's flush rounds land it and retry — it is never discarded.
  - P130 is an enforced invariant: a fresh CAW grant over an OPEN lineage →
    `P130-FALSE-FRESH-REFUSED` + shutdown (knob `false_fresh_enforce`, default 1).
  - Knobs: `agmeta_inval_enforce` (default 1), `false_fresh_enforce` (default 1),
    `single_era_hint_keep` (diagnostic, default 1; 0 re-creates the trigger for the
    `p130`/`p131` arms of `tests/lone_mount_create.sh`).

**Invariant, stated:** local committed metadata is landed BEFORE the CAW authority is
yielded (release drain), never after re-acquiring it; a fresh acquire that finds
un-landed local AG metadata has no safe continuation and stops loudly.

**Open beside it:** D-0354 (single-node-era epoch-0 images vs. token-enforced foreign
replay after a lone crash — needs the directed crash test) and D-0355 (a lone node
cannot remount after its own dirty shutdown: mount-window death has no replay hook).

## 2026-08-28 (sess433-434): a lone node mints REAL epochs — D-0354 candidate A (0.41.0)

**Measured defect (sess433, both `foreign_replay_token_enforce` settings).** Every image a
lone node journals is UNTAGGED (`P227-TOKENSUM ... untagged=6`), because the single-node
fast path granted in memory (no slot image, epoch 0) and `mxfs_buf_item_wants_authority`
exempted single-node mounts from the trailer.  After the lone node crashes, the first
successor's foreign replay refuses the slice (`-117`) and quarantines its AG domain — the
lone era's fsync-acknowledged work is unrecoverable by ANY successor.  D-0355 closed the
remount path (0.39.13) but the images it replays are still refused for this reason.

**Ruling** (`docs/rulings/d0354-mint-durable-epoch-single-node.md`):
ship candidate A — single-node mode mints real durable epochs through the normal CAW
grant state machine; no memory-only authority of any kind.  Stop-ships: (3) joiner
barrier on an incumbent HB "single" feature bit, (4) mixed-version gate rejecting a
memory-only-era peer.  Invariant: *a grant must not change identity while journal
records bearing its token can still require replay.*

**Step 1 (0.41.0) — what changed:**

- `dlm/dlm_caw.c`: every `single_node` memory-only shortcut removed (lock/unlock/convert
  fast paths, `set_dir_block0`, `held`, `granted_mode`, open_* probes, `ex_count`,
  `self_held_scan`, `force_release_self`).  A lone node's AG and inode grants are on-disk
  CAW grants with real `ex_grant_epoch`s.  Kept: `bast_poll_fn` skips polling while
  `single_node` (no peer can be asking — until step 3 makes the joiner wait for the
  incumbent's poll to start).  `MXFS_GAUTH_SINGLE_NODE` is no longer produced; the
  0.39.11 `pag_mxfs_grant_single` hint and its P243 branches are dead but harmless.
- `pal/linux/xfs_buf_item.c mxfs_buf_item_wants_authority`: `mp && mp->m_mxfs_dlm` —
  no single-node exemption.  Lone-era images carry v3 tokens naming the real epoch.
- `xfs/xfs_trans_buf.c`: the three `!is_single_node` gates on `mxfs_ag_meta_track` /
  `mxfs_dir_bmbt_track` / `mxfs_dir_data_track` removed — deferred-release tracking and
  tenure-epoch stamps exist from the first dirtying, since a joining peer can BAST a
  lone-era grant.
- `xfs/xfs_mxfs_dlm.c mxfs_dlm_invalidate_cached_views`: the v0.3.86 single→multi
  SURRENDER (clear `pag_dlm_cached`/epoch/lineage, force every idle inode to NL+stale)
  is gone.  With real grants the surrender re-enters `caw_lock_body`'s self-hold check
  with a zero epoch, fails closed (-EDEADLK), releases and RE-MINTS — and every image
  journaled under the old epoch becomes `staleep` to a successor.  Retained grants are
  what a cohort member has: held on disk, revocable by BAST.  The AG-meta buffer
  invalidation (FUA re-read) is kept; the join barrier's retained-buffer verdict is
  unchanged.
- `mxfs_dlm_caw_set_single_node` single→multi: nothing to promote, nothing to drop.

**Cost:** a lone node pays one CAW round trip per first acquire of an AG/inode — the same
cost a cohort member pays (budget: measure `bench/rsync_bench.sh` lone vs 0.40.1).

**Verification plan:** `tests/lone_mount_create.sh fixed` (D-0353 regression),
`tests/lone_crash_replay.sh` with enforce=1 (expect `replay complete`, file present,
zero `untagged`; the enforce=0 arm is shadow-only by definition and is a measurement
arm only), `tests/d379b_dirty_depart_peer_fence.sh`, then the 32/caw board.

**Step 1 measured (0.41.0, sess434):** `fixed` PASS; lone rsync 3.1 s (0.40.1: 2.4 s;
native XFS 3-4 s — under the budget rule 2× ceiling); `d379b` PASS; **lone_crash_replay
enforce1 FAIL** — but for a NEW reason: `untagged=0 notheld=0 staleep=0` (the tokens
and the manifest now agree) and `winc=3`: the survivor's replay window still held the
PREVIOUS incarnation's last transaction (already published by the d379b lap minutes
earlier) beside the crashed lone incarnation's one transaction.

### Lap 2 (0.41.1): the replay window keeps the previous incarnation's last record

**Mechanism (code-verified, journal-measured).** Upstream `xlog_find_tail` →
`xlog_set_state` seeds `ail_head_lsn` with the LAST OLD RECORD's own LSN.  After a
mount-time recovery with an empty AIL, `xlog_assign_tail_lsn` returns exactly that, so
the new incarnation's first checkpoint carries `h_tail_lsn` pointing AT the previous
incarnation's record.  Upstream tolerates it (replay is LSN-idempotent); MXFS's
incarnation-bound tokens make it a `winc` refusal, which the atomic-skip rule turns into
`P227-FR-TORN-UNPUBLISHED` → the whole slice quarantined.  Any node that recovers a dirty
slice at mount — its own crash (pass 1) or an ADOPTED already-published slice (pass 2) —
and crashes again after few checkpoints is exposed; a lone node is simply the shortest
path there.

**Fixes (design-consult reviewed):**

1. `P308-LOG-INCARNATION-BOUNDARY` (`xfs_log.c xfs_log_mount_finish`): after
   `xlog_recover_finish` + log force + AIL drain, with the covering worker stopped, a
   standard unmount record is written and forced.  The empty-AIL tail fallback is then
   the boundary itself; a mid-window unmount op is ignored by recovery, so no later
   window reaches back across it.  Skipped (and warned) only when the summary counters
   are sick, preserving upstream's recalculation rule.
2. `P310-FR-PREINCARNATION-SKIP` — the certificate the ruling required before age may
   be trusted: the claim loop stamps `MXFS_HB_FEAT_ADOPTED` into every record of a
   pass-2 (fresh-claim) incarnation; fence time captures it as
   `MXFS_RECOV_F_VICTIM_ADOPTED`; the shadow evaluator (`victim_adopted`, printed in
   `P273-SHADOW-CAP`) turns `owner_epoch != victim_epoch` on such a victim into
   `MXFS_RI_VERDICT_PREINC`, and `mxfs_classify_untrusted_txn` skips that whole
   transaction clean (`MXFS_TXNV_PREINC`: no images, no inode items, no intents into the
   census, no quarantine domain).  A pass-1 own-stamp reclaim carries no bit, so its
   unpublished predecessor records still refuse (that path is
   D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE's).  This also covers the residual window a
   crash between the HB claim and the boundary leaves.
3. `P309-LOGTAIL` diagnostics in `xlog_find_tail` (own/adopted/foreign: head_blk,
   tail_blk, tail_lsn, clean) — the evidence line for both fixes.
4. Stop-ship 3 of the candidate-A ruling: the lone node's BAST poll thread now runs
   unconditionally (`dlm_caw.c bast_poll_fn`, the `single_node` skip removed) — the
   consult preferred it to a heartbeat feature-bit join barrier.  Stop-ship 4:
   `MXFS_PROTO_GEN` 10 → 11 (gen-10 memory-only lone grants are incompatible).

**Lap 2 measured (0.41.1, sess434 chain 6 / sess435 harvest):** both
`lone_crash_replay enforce1` arms replayed and the fsync'd file was present
(`P273 winc=0`, `wapply=6`, `P163-RECOVERY-COMPLETE`, barrier `quarantined=0x0`,
`file=1`; the harness's `quarantine=1` was its own `grep 'quarantin'` matching
`quarantined=0x0` — fixed).

**sess436 — the intent/done census was vacuous under enforcement.**  `mxfs_icensus_note`
was called inside the per-item loop of `xlog_recover_items_pass2`, which the
whole-transaction verdict switch (`SKIP`/`SBCLEAN`/`PREINC` → `return 0`) leaves before
the loop runs.  With `foreign_replay_token_enforce=1` every dirty-victim transaction is
`ATOMIC-SKIP`ped whole, so a victim destroyed inside a held EFD transaction
(`mxfs.dbg_efd_hold_ms`, 0.41.7; `tests/d_intents_undischarged_verify.sh burst`) replayed
as two skipped transactions and `P226-ICENSUS` printed `intents=0 dones=0 open=0` — the
`INTENTS_UNDISCHARGED` refusal could never fire.  0.41.8 runs the census as a pre-pass
over every batch's items before the verdict, for every verdict except `PREINC` (which is
clean by the P310 certificate above).  But the e1b arm (test5, an ADOPTED dirty slot) printed
`P308 ... did NOT advance ail_head_lsn (0x100000012)`: the boundary was written and
not in force, and the replay succeeded only through P310 (`preinc_images=6`, `wskip=6`).

### Lap 3 (0.41.2): the boundary record does not move the AIL head

`xlog_unmount_write` goes through `xlog_write` directly, and `ail_head_lsn` is written
only by `xlog_cil_ail_insert` (checkpoint commit) and by recovery's tail seeding — a
record that bypasses the CIL never advances it, so the empty-AIL tail fallback kept
returning the old record.  `mxfs_log_head_past_boundary` (called right after the
boundary write) moves the head to `xlog_assign_lsn(l_curr_cycle, l_curr_block)` — the
LSN the next record will take, which is what `xlog_find_tail` derives for a clean log
(`after_umount_blk`) — in checkpoint order: head under `ail_lock`,
`xfs_ail_update_finish(NULLCOMMITLSN)` recomputes `l_tail_lsn`/`l_tail_space`, then
`xlog_grant_return_space(old, new)` returns the consumed span to the grant heads.
Verification: `tests/sess435_chain8_0412.sh` — A must print `P308 ... 0xX -> 0xY` with
no `did NOT advance`, B's `P309-LOGTAIL foreign` tail must sit beyond the old record
and `P310` must not be needed (`preinc` absent) for the replay to complete.

## Unmount: the grants are published last

The release-side drain above is a per-AG statement; the unmount has to make it
for every AG at once, and it has one constraint the cooperative release does
not: the unmounting node stops proving its liveness (the heartbeat thread is
joined) before the log is torn down, and a grant held past that point is held
by a node peers are entitled to read as dead.  So the unmount cannot keep its
grants until the very end.  It publishes them instead at the last moment at
which it is still alive, and every piece of metadata work that could dirty an
allocation group is done before that moment:

1. Every producer that could still log is stopped first — foreign-slice
   replay, the deferred reap, the destage kick, speculative-allocation garbage
   collection.
2. The filesystem-level teardown that mutates allocation groups runs under
   live grants: deferred inode inactivation (AGI, inode btrees), the return of
   per-AG reservations, quota and realtime teardown, the release of the root
   and metadata-directory inodes.  Inactivation is then disabled, so nothing
   can queue a transaction behind the steps that follow.
3. The final superblock summary is written under its cluster lock and the
   mount is sealed; the log is forced, the whole AIL pushed and the buffer
   target waited, so no dirty AG-metadata or inode-cluster buffer survives.
4. The release itself drains every allocation group — fresh cluster buffers,
   inode clusters, AG metadata, pointee before pointer — forces the log,
   makes a second metadata pass, flushes the device once, and only then
   unlocks the grants one by one.
5. What remains after publication is the log covering and the unmount
   record, which touch no allocation group.  Inode reclaim also remains
   there, because it drops per-inode cluster locks and after step 3 has only
   clean inodes to free.

Mount is the mirror image — the lock manager is alive before any filesystem
work begins — and the two must stay symmetric.  The departure accounting
counts every AG-metadata and inode-cluster write on both sides of the
publication, every AG acquire and every inactivation enqueue after it, and
prints them once per unmount; a nonzero on the after side is a violation of
this ordering, whatever produced it.

## 2026-09-02 (sess470-472): the untrusted iget reads the inobt unlocked — D-0527 (0.64.15)

An `XFS_IGET_UNTRUSTED` iget (NFS handles / `open_by_handle_at`, bulkstat and
inumbers, the P88 reap retry, the orphan scan's post-unlock iget, the sweep)
decides "is this inode number allocated?" in `xfs_imap_lookup`: an AGI read
plus an inobt walk.  On MXFS those buffers are refreshed only when this node
ACQUIRES the AG (Invariant 1 drain on the releaser, FUA-fresh reads on the
acquirer); read outside the AG DLM they are whatever this node last cached,
so a peer's allocation of the number stays invisible for an unbounded time
and a valid reference reads as FREE / NOT-IN-ANY-CHUNK (`-EINVAL`).  First
seen through the dir-sharding manifest (D-0526 root b), then measured
directly by `tests/d0527_untrusted_iget_peer.sh` (chain 110, 0.64.12): 12 of
24 handle opens of peer-created files failed ESTALE with
`P-IMAP-UNTRUSTED-NOREC` on the serving node.

Fix (sess470 design-consult answer D, landed 0.64.15 in `xfs_iget_cache_miss`):
exactly the `xfs_imap` call is bracketed with `mxfs_ag_dlm_lock` /
`mxfs_ag_dlm_unlock` when the mount is multi-node and the iget is untrusted.
The acquire is the blocking class (a caller already holding the AG nests
through `pag_dlm_holders`), the release is the cached one (the grant stays
with this node until a peer BASTs it), and the bracket ends before the inode
DLM acquire so the ILOCK → AG order is never inverted.  A lock failure is
returned as-is (`P-IMAP-UNTRUSTED-AGLOCK-FAIL`; EIO for a quarantined AG),
never as "free".  The read-only module parameter
`untrusted_imap_aglock_n` counts brackets so the verification can prove the
lookup ran under the lock rather than the cache happening to be fresh.
Verification: chain 110 rerun on 0.64.15 (three pairings, RESULT PASS with
`P-IMAP-UNTRUSTED-*` = 0 and the counter advancing).
