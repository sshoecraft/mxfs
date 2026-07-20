# MXFS v0.2.4 → AG-metadata fix analysis

## Bug
AG free-space btree corruption under regular-file dd workload. Trips
`xfs_alloc.c:2105 ltbno+ltlen>bno` → SHUTDOWN_CORRUPT_INCORE.
Root cause: AGF/AGI/AGFL/free-space-btree buffers are not synchronized
across DLM AG-lock grants — local buffer cache holds stale view of AG
state after another node modified it.

## Why naive stale-on-acquire (this session, reverted) failed
Tried `xfs_buf_incore` + `xfs_buf_stale` of the three fixed AG-header
buffers in `mxfs_ag_dlm_lock` fresh-acquire path. Corruption faster
(70s vs 80s baseline) + EIO. Reason: AG-headers were DIRTY in our cache
because they had not been flushed during prior `mxfs_ag_dlm_unlock`.
Staling discarded our own un-persisted writes.

## Required fix shape
**Bidirectional, atomic w.r.t. DLM lock state**:
1. **Release-side**: flush dirtied AG-metadata buffers BEFORE releasing
   DLM AG-lock. Cannot use `xfs_log_force(SYNC) + xfs_ail_push_all_sync`
   in unlock path (livelocks under concurrent allocation — known failed
   approach).
2. **Acquire-side**: invalidate AG-metadata buffers on FRESH DLM acquire
   (not nested re-acquire), so we re-read peer's writes from disk.

## Release-side mechanism (correct approach)
Per-AG list of dirtied AG-header / btree-block buffers, **parallel to
`pag_mxfs_alloc_buflist`** (which already handles fresh cluster buffers).
Submit via `xfs_buf_delwri_submit` in `mxfs_ag_dlm_unlock`.
Hook point: `xfs_trans_log_buf` for AGF/AGI/AGFL/btree blocks — enqueue
onto the per-AG list when transaction logs an AG-metadata buffer.

## Acquire-side mechanism (two options)
1. Walk `mp->m_ddev_targp->bt_cache` rhashtable, stale buffers whose
   `bm_bn` falls in `[ag_start, ag_start + agblocks_in_BBSIZE)`.
2. Use the per-AG dirty list precisely (only the buffers we touched).

State.md recommends approach 1 (range-walk) — closer to mxfs.1 design,
self-contained. Approach 2 is more precise.

## Hook locations to identify
- `mxfs_ag_dlm_lock` — fresh-acquire branch: invalidate range
- `mxfs_ag_dlm_unlock` — pre-release: submit per-AG dirty list
- `xfs_trans_log_buf` (or wrapper): identify AG-metadata buffers and
  enqueue onto current AG's per-AG dirty list

## Reference implementation
mxfs.1 `libmxfs/alloc.c:lock_ag` (line 270+) — battle-tested at 32 nodes.

## Constraints / DO NOT REPEAT
- No `xfs_log_force(SYNC) + xfs_ail_push_all_sync + blkdev_issue_flush`
  in `mxfs_ag_dlm_unlock` — AIL livelock.
- No bare `xfs_bwrite(fbuf)` — NULL-ptr oops.
- No `xfs_trans_log_buf` of cluster buffer in `xfs_ialloc_inode_init`
  — log-reservation deadlock.
- Stale-on-acquire alone (without release-side flush) → loses dirty
  writes (this session's failed attempt).

## Files likely to touch
- `xfs/xfs_mxfs_dlm.c` — DLM AG lock/unlock hooks, invalidate helper
- `xfs/libxfs/xfs_ag.h` (or perag struct) — add `pag_mxfs_agmeta_buflist`
- `xfs/xfs_trans_buf.c` — hook AG-metadata buffer logging
- Possibly `xfs/xfs_buf.c` — range-invalidate helper

## Open design questions for user
1. Approach 1 (rhashtable walk) vs Approach 2 (precise per-AG list also
   on acquire) — state.md recommends 1, but 2 is symmetric with the
   release-side list.
2. How to identify "AG-metadata buffer" in `xfs_trans_log_buf` — is
   `bp->b_ops` enough (xfs_agf_buf_ops, xfs_agi_buf_ops, xfs_agfl_buf_ops,
   xfs_allocbt_buf_ops, etc.)?
3. Re-evaluate Fix A (cluster-stale in `xfs_iget_cache_miss`) — could it
   have been masking AGF staleness? state.md flags this as worth checking.
