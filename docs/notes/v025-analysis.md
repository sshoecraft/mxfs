# v0.2.5 Attempt 2 — Analysis

## Hook-point research findings

### `iop_committed(lip, lsn)` — WRONG hook for our purpose
- Defined in `xfs_trans.h:81`.
- Called from `xlog_cil_ail_insert` in `xfs_log_cil.c:897` — this is the **AIL INSERT** path, fired when a CIL checkpoint commits.
- Semantics: WAL is durable (log record written), but the buffer's home-location bytes are NOT yet on disk. Buffer is then in AIL waiting for AIL push → writeback.
- A peer reading the AGF/AGI block from its on-disk home location would still see stale bytes after iop_committed.
- The previous attempt's hook-point assumption ("iop_committed = on-disk") was incorrect.

### `bp->b_iodone` — RIGHT hook
- Per-buffer field in `struct xfs_buf` (xfs_buf.h:190).
- Called from `__xfs_buf_ioend` (xfs_buf.c:1201) on every successful WRITE completion, after `bp->b_log_item ? xfs_buf_item_done(bp)`.
- Existing users (mutually exclusive with AG-meta buffers):
  - `xfs_buf_inode_iodone` — set on inode buffers (b_ops = xfs_inode_buf_ops via XFS_BLFT_DINO_BUF)
  - `xfs_buf_dquot_iodone` — set on dquot buffers
- AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt/rmapbt/refcountbt buffers never set `b_iodone` upstream — slot is free.

## DLM grant caching

- `mxfs_v5_dlm_ag_unlock` calls `mxfs_dlm_caw_unlock` immediately — no caching layer.
- BUT: `mxfs_dlm_caw_lock` has a "we already hold it" fast path (dlm_caw.c:621-627) that checks the on-disk slot's `node_held_mode`. If our deferred-release scheme keeps the EX bit on disk, a re-acquire returns success without disk I/O and without contending with peers.
- So: as long as we DON'T call `mxfs_v5_dlm_ag_unlock` until AG-meta is on disk, local re-acquires are cheap (no DLM round trip to disk for the lock check — the fast path is in-memory tracked-held check first, then disk if needed).

## Race / concurrency notes
- Existing `mxfs_ag_dlm_unlock` releases `pag_dlm_lock` BEFORE calling `mxfs_v5_dlm_ag_unlock` (xfs_mxfs_dlm.c:861, 881). Our deferred-release path will follow the same pattern.
- Lock-path / iodone-path / unlock-path coordinate via `pag_dlm_lock` + new `pag_dlm_release_pending` flag + atomic `pag_dlm_meta_pending` counter.
- Deduplication of log_buf calls within a single dirty epoch: use `XFS_BLI_MXFS_AGMETA_TRACKED` flag on `bli_flags`. The `bli` is destroyed by `xfs_buf_item_done` when writeback completes; next dirty epoch starts with a fresh bli (flags=0).

## Design

### New per-AG state (xfs_ag.h `struct xfs_perag`):
```c
bool        pag_dlm_release_pending;  /* deferred DLM release */
atomic_t    pag_dlm_meta_pending;     /* AG-meta bufs awaiting writeback */
```

### New flag (xfs_buf_item.h):
```c
#define XFS_BLI_MXFS_AGMETA_TRACKED (1u << 8)
```

### Hook in `xfs_trans_log_buf` (xfs_trans_buf.c):
- After `xfs_buf_item_log(bip, ...)`:
- If `mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(...) && mxfs_buf_is_ag_metadata(bp) && !(bli_flags & MXFS_AGMETA_TRACKED)`:
  - Set the flag.
  - Look up owning AG, get pag.
  - `xfs_buf_hold(bp)` — extra ref so bp stays alive until our iodone.
  - `atomic_inc(&pag->pag_dlm_meta_pending)`
  - Save existing `b_iodone` (must be NULL for AG-meta), set `b_iodone = mxfs_dlm_ag_meta_iodone`.
  - `xfs_perag_put(pag)` — drop our short-lived ref; meta_pending is the persistent ref.

### `mxfs_dlm_ag_meta_iodone(bp)`:
- Compute agno from `bp->b_maps[0].bm_bn / sb_agblocks`.
- `pag = xfs_perag_get(mp, agno)`.
- `if (atomic_dec_return(&pag->pag_dlm_meta_pending) == 0)`:
  - Lock `pag_dlm_lock`. If `release_pending && holders == 0`: `release_pending = false; do_release = true`.
  - Unlock. If do_release: `mxfs_v5_dlm_ag_unlock(...)`.
- `xfs_perag_put(pag)`.
- `xfs_buf_rele(bp)` — drop the extra ref from log_buf hook.

### Modify `mxfs_ag_dlm_lock`:
- Lock `pag_dlm_lock`. If `holders == 0`:
  - If `release_pending`: clear it (we still hold EX, no DLM call needed).
  - Else: `mxfs_v5_dlm_ag_lock(...)`. (Eventually add acquire-side rhashtable invalidate here.)
- `holders++`. Unlock.

### Modify `mxfs_ag_dlm_unlock` (last-holder branch):
- Existing cluster-buf drain logic stays.
- After cluster drain + blkdev_flush: check `meta_pending`. If > 0: set `release_pending = true`. Else: actually `mxfs_v5_dlm_ag_unlock(...)`.

### `mxfs_buf_is_ag_metadata(bp)`:
- Match `bp->b_ops` against the 9 AG-meta types: agf/agi/agfl/bnobt/cntbt/inobt/finobt/rmapbt/refcountbt.

## What about the acquire-side invalidate?
- The original design doc (v0.2.5 attempt 1) included a rhashtable walk to stale buffers in the acquired AG range.
- That part is still needed — even with deferred release, our local cache may have STALE buffers that a peer wrote to since we last released.
- Implement as a follow-on after the release-side machinery is validated.

## Files to modify (v0.2.5 attempt 2)
1. `xfs/libxfs/xfs_ag.h` — add `pag_dlm_release_pending`, `pag_dlm_meta_pending` to `struct xfs_perag`.
2. `xfs/libxfs/xfs_ag.c` — initialize new fields in `xfs_perag_alloc`.
3. `xfs/xfs_buf_item.h` — add `XFS_BLI_MXFS_AGMETA_TRACKED`.
4. `xfs/xfs_mxfs_dlm.h` — declare `mxfs_buf_is_ag_metadata`, `mxfs_ag_meta_track`, `mxfs_dlm_ag_meta_iodone`.
5. `xfs/xfs_mxfs_dlm.c` — implement the three new functions; modify `mxfs_ag_dlm_lock`/`unlock`.
6. `xfs/xfs_trans_buf.c` — call `mxfs_ag_meta_track(tp, bp)` from `xfs_trans_log_buf`.
7. `VERSION` — bump 0.2.4 → 0.2.5.

## Test
- Build clean.
- Reproducer from state.md "AG-metadata bug reproducer". Expect no `Internal error ltbno + ltlen > bno`, no `SHUTDOWN_CORRUPT_INCORE`.
- Mkdir regression — should still pass.
