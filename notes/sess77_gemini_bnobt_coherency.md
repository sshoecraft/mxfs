# sess77 — Gemini design for the AG bnobt cross-node lost-update / double-free

**Date:** 2026-06-04 (sess77). Via mcp__ask_gemini__query, max_tokens OMITTED
(finish_reason STOP, output 1610 / thoughts 12200 / total 16172 — complete).

## The bug (fresh repro this session — cross_write_read criterion shutdown)
`Internal error "ltbno + ltlen > bno" xfs_alloc.c:2244` in `xfs_free_ag_extent`,
called from `rm -> xfs_inactive -> xfs_itruncate_extents -> __xfs_free_extent`.
- P47 verdict: `DISK-LIVE-same-gen => A-lost-removal` — inode 2097414 is a LIVE,
  same-incarnation reg file that legitimately owns block 11, but bnobt shows 11
  already free (record [9..32)). Double-free.
- P28: bnobt leaf `disk_differs=0 in_ail=0` — the stale image REACHED DISK.
- So the bnobt update that removed block 11 from free-space (when 2097414 was
  allocated it) was LOST — overwritten by a later bnobt write re-adding 11 free.

## Gemini's ROOT diagnosis
The flaw is on the **RELEASE side**, not the acquire-side lazy invalidation.
MXFS drops the on-disk AG-DLM lock while local memory still holds **CIL-pinned**
(un-checkpointed) bnobt updates for that AG. The release drain
(`mxfs_dlm_ag_drain_meta_buffers`) only writes buffers that are IN_AIL or have a
non-empty b_li_list; it SKIPS a bnobt buffer pinned-in-CIL-but-not-yet-AIL (P73).
So an AG is unlocked on disk with a just-committed-to-CIL change still pinned and
NOT on disk. Peer acquires, FUA-reads disk, gets the OLD image. Then this node
(or another) writes its stale base back → lost update reaches disk → double-free.

## The FIX (architecturally correct, GFS2-style demote)
Keep the gen-counter lazy invalidation on ACQUIRE. Make the RELEASE path leave
every AG-meta buffer **strictly clean** (not pinned / not in_ail / not dirty), so
the next acquire's invalidation can safely `XBF_DONE`-clear (or xfs_buf_stale)
WITHOUT hitting the pinned wall.

### AG-DLM RELEASE sequence (in the DLM callback / bast path — holds NO XFS txn,
### ILOCK, or AGF/AGI buffer locks):
1. `xfs_log_force(mp, XFS_LOG_SYNC)` — forces CIL → on-disk journal, dropping
   b_pin_count to 0 for ALL AG buffers. (Optimization: lockless pre-walk the AG
   buf hash; if none `xfs_buf_ispinned()`, skip the force.)
2. `mxfs_dlm_ag_drain_meta_buffers(pag)` — now every dirty buffer is unpinned and
   can be written synchronously (`xfs_bwrite`, which on I/O completion removes the
   BLI from the AIL and clears dirty).
3. on-disk CAW AG-DLM unlock.

### AG-DLM ACQUIRE sequence (unchanged logic, now safe):
`mxfs_ag_meta_invalidate_stale`: if `b_mxfs_ag_gen < gen`, the buffer is now
GUARANTEED clean (release invariant), so `bp->b_flags &= ~XBF_DONE` (or
xfs_buf_stale) ALWAYS succeeds → next read FUA-re-reads peer's committed image.

### Deadlock analysis (passes all constraints)
- `xfs_log_force` needs log ticket locks (xc_ctx_lock) but does NOT acquire inode
  ILOCKs — only blocks on log I/O. Cannot deadlock xfsaild or the CAW poller,
  PROVIDED the release point holds no ILOCK/AGF/AGI. VERIFY the release context.
- Pinned buffers are forcibly unpinned before the lock leaves the node → the
  "can't refresh pinned buffer" wall disappears.
- Single-node fast path preserved: lock never released → log_force/bwrite never
  called → normal background AIL flush. No perf penalty.

### GFS2 parallel
`gfs2_glock_dq` demote = `gfs2_log_flush()` (== our xfs_log_force, unpins) +
`gfs2_ail_empty_gl()` (== our xfs_bwrite loop) + page evict (we use gen-counters).
MXFS was missing step 1 (the log force) → blocks trapped behind the CIL pin-wall.

## Implementation anchors
- AG BAST/release: `mxfs_dlm_ag_bast_work_fn` (xfs_mxfs_dlm.c ~L3649 caller area),
  Phase 2 drain pipeline before `mxfs_v5_dlm_ag_unlock`. Add the log force at the
  TOP of Phase 2, before drain_meta_buffers.
- Drain: `mxfs_dlm_ag_drain_meta_buffers` (~L<find>) — extend to write back the
  now-unpinned dirty buffers (currently filters to IN_AIL/li_list only).
- Invalidate: `mxfs_ag_meta_invalidate_stale` (~L2710) — once release-clean is
  guaranteed, the pinned/in_ail/dirty SKIP branch becomes dead (can assert).
- Invariant #1 (CLAUDE.md): "No on-disk DLM unlock without successful drain
  pipeline" — this fix STRENGTHENS it (adds the missing CIL force).
