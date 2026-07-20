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
