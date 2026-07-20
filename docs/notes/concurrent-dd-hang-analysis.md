# MXFS v0.2.6 — Concurrent-dd Hang Analysis

Started: 2026-04-25 (third session of the day, post v0.2.6)

## Bug

Repro from state.md "Open issues for next session":
1. mkfs + mount T1 (192.168.120.186) + T2 (192.168.120.182).
2. T1: `dd 1GB → rm → drop_caches`; T2: `drop_caches`.
3. Concurrent: `T1 dd perf_t1 1GB & T2 dd perf_t2 1GB & wait`.
4. T1 `rm perf_t1 perf_t2` — **hangs**. Subsequent `ls /mnt/mxfs` blocks indefinitely.

Sequential cross-node touch/rm (validated v0.2.6) still passes. The dd workload is what breaks.

## Suspected mechanism (pre-instrumentation hypotheses)

### H1 — Cross-AG deadlock during defer chain

`xfs_inactive_ifree` holds the AG DLM lock for the inode's AG, but `xfs_inactive_truncate`
that runs BEFORE `xfs_inactive_ifree` frees data extents via `xfs_defer_finish`. Each
extent free hits `__xfs_free_extent` → `mxfs_ag_dlm_lock(target_ag)`. If the defer
queue processes free items in non-monotonic AG order, T1 may hold AG-3 wanting AG-1
while T2 (concurrent dd alloc finishing async) holds AG-1 wanting AG-3. Cluster
deadlock.

### H2 — `pag_dlm_meta_pending` leak

`mxfs_ag_meta_track` increments on `xfs_trans_log_buf`; the matching decrement is
`mxfs_dlm_ag_meta_iodone` which only fires on disk-write completion via
`__xfs_buf_ioend`. Counter cannot drain if:

- trans is cancelled (`xfs_trans_cancel`) after a buffer was logged → bli freed without
  write completing.
- buffer is staled (`xfs_buf_stale`) before it writes → write skipped, iodone never
  fires.
- buffer is relogged across epochs in a way that the per-bli `XFS_BLI_MXFS_AGMETA_TRACKED`
  flag misses (e.g. bli lifecycle gap not seen in code so far).

If counter leaks, `mxfs_ag_dlm_unlock` sets `pag_dlm_release_pending = true`, never
fires the actual `mxfs_v5_dlm_ag_unlock`. T2's next acquire on that AG blocks at the
DLM (CAW or TCP) layer indefinitely. T1 also blocks on next own re-acquire because
the state machine in `mxfs_ag_dlm_lock` says "still hold EX, release_pending=false now"
but iodone may concurrently fire and set release_pending again. Hard to reason without
a state diagram.

### H3 — `xfs_ail_push_all_sync` over-reach

The push drains the **entire** local AIL, which is overkill. If the AIL contains an
item that requires re-acquiring our own AG DLM (it shouldn't normally — buffer flushing
is just I/O), or if a buffer is pinned by a still-running transaction (e.g. the tail
end of T1's own dd writeback), `ail_push_all_sync` busy-waits forever.

Targeted alternative: just push the inode log item for the freed inode (or its cluster
buffer's bli) — bounded work, no risk of wedging on unrelated items.

## Architecture map (relevant subsystems)

- `xfs/xfs_inode.c::xfs_inactive_ifree` (lines ~1287-1382) — wraps inode-free trans
  with mxfs_ag_dlm_lock + post-commit sync flush + unlock. **v0.2.6 addition.**
- `xfs/xfs_mxfs_dlm.c::mxfs_ag_dlm_lock` (lines 803-864) — per-AG DLM acquire,
  fresh-acquire branch invalidates `pag_bcache` AG-meta buffers via
  `mxfs_dlm_invalidate_ag_meta`.
- `xfs/xfs_mxfs_dlm.c::mxfs_ag_dlm_unlock` (lines 870-959) — last-holder release,
  drains `pag_mxfs_alloc_buflist`, defers DLM release if `pag_dlm_meta_pending > 0`.
- `xfs/xfs_mxfs_dlm.c::mxfs_ag_meta_track` (lines 1213-1254) — hooked from
  `xfs_trans_log_buf` for AG-meta b_ops; increments counter, sets b_iodone.
- `xfs/xfs_mxfs_dlm.c::mxfs_dlm_ag_meta_iodone` (lines 1130-1184) — write-completion
  callback; decrements counter; fires deferred release on drain.
- `xfs/xfs_trans_buf.c::xfs_trans_log_buf` (lines 548-580) — calls
  `mxfs_ag_meta_track` for AG-meta in multi-node mode.

## Plan

1. Add tracing macros (compile-time via `#ifdef MXFS_TRACE_AG_DLM`) into the four DLM
   functions above so each emits one line per call with: agno, holders before/after,
   meta_pending before/after, release_pending before/after, caller's PID and comm.
2. Clean rebuild.
3. Deploy and run reproducer. Capture full dmesg from both nodes at the point T1 rm
   hangs.
4. Identify which AG, which counter is wedged, which thread holds the lock.
5. Apply targeted fix.

## Files I have read so far

- /src/mxfs/CLAUDE.md, /src/mxfs/state.md, /src/mxfs/dir-coherency-analysis.md
- /src/mxfs/xfs/xfs_mxfs_dlm.c (lines 780-1326)
- /src/mxfs/xfs/xfs_inode.c (lines 1260-1419)

## Root cause — confirmed by sysrq-w on hung iter-3

**`mxfs_ag_dlm_lock` calls `mxfs_v5_dlm_ag_lock` (CAW round-trip with up to 120s
sleep loop) while holding `pag->pag_dlm_lock`.**  In parallel,
`mxfs_dlm_ag_meta_iodone` (running on the xfs-buf workqueue, fired when an
AG-metadata buffer's writeback completes) needs that same `pag_dlm_lock` to
test/clear `pag_dlm_release_pending` and fire the deferred
`mxfs_v5_dlm_ag_unlock`.

Captured stacks during the iter-3 hang:

```
PID 376 (xfs-inodegc/sda):
  mxfs_pal_sleep_ms / msleep
  caw_wait_for_grant.isra.0+0x203
  mxfs_dlm_caw_lock+0x6e3
  mxfs_v5_dlm_ag_lock+0x79
  mxfs_ag_dlm_lock+0xec   ← pag_dlm_lock held HERE
  xfs_inactive_ifree+0xa6
  xfs_inactive
  xfs_inodegc_worker

PID 1868 (xfs-buf/sda):
  __mutex_lock                         ← blocked on pag_dlm_lock
  mxfs_dlm_ag_meta_iodone+0xc3
  __xfs_buf_ioend
  xfs_buf_ioend_work
```

Result: the xfs-buf iodone for an AG-meta buffer is wedged on a per-AG mutex
held by inodegc, which itself is wedged in a 120s CAW poll loop.  After the
120s timeout fires `-EAGAIN`/`-110`, `xfs_inactive_ifree` retries and the
sleep loop restarts — wedging the same iodone again indefinitely.

When the deferred AG-meta iodone never runs, the corresponding AG-metadata
buffer never reaches its on-disk home location, and umount's later
`xfs_sb_write_verify` fails ("SB summary counter sanity check failed") because
the in-memory super counters were updated for transactions whose AGF/AGI/inobt
backing buffers never persisted.  That's the `0x8 / xfs_buf_submit:1467`
shutdown.

## Fix

Drop `pag_dlm_lock` before calling `mxfs_v5_dlm_ag_lock`.  Use a separate
`pag_dlm_acquire_lock` mutex to serialize concurrent fresh-acquire attempts
on this node so only one thread drives a CAW grant for a given AG at a time.
The iodone path only ever needs `pag_dlm_lock` (briefly), so it is no longer
blocked behind the multi-second CAW poll loop.

Files to touch:
- `xfs/libxfs/xfs_ag.h` — add `pag_dlm_acquire_lock`.
- `xfs/libxfs/xfs_ag.c` — `mutex_init` it in `xfs_initialize_perag`.
- `xfs/xfs_mxfs_dlm.c::mxfs_ag_dlm_lock` — rewrite to release `pag_dlm_lock`
  across `mxfs_v5_dlm_ag_lock`, with `pag_dlm_acquire_lock` serializing the
  CAW path.

## Status

- VMs starting (sudo virsh start test1/test2 issued).
- Reproduced the hang on iter-3 of repeated full reproducer.
- Captured stacks confirming the deadlock structure above.
- Applied fix (v0.2.7 — see top-level VERSION).
- Validated single-shot canonical v0.2.5 reproducer: PASS clean (no
  shutdown, both files visible to T1, rm both succeeds).
- Validated second iteration of full reproducer: PASS clean.
- Multi-iteration stress (5+ iterations) still hits a *separate* cross-node
  coherency issue: T1 trips `Free inode 0x83 not marked free!` (mode 0x81a4)
  via `xfs_dialloc_ag`, and shutdowns ensue.  This is a residual v0.2.5/v0.2.6
  AG-metadata-coherency hole — same family of corruption v0.2.6 was working
  on, but not yet fully closed.  It was *masked* before by the deadlock (the
  deadlock prevented inodegc from reaching the alloc path that observes the
  stale inode).  Out of scope for the hang fix, but the next session needs to
  pick this up.

## Files modified in v0.2.9 (cumulative on v0.2.7+v0.2.8 work)

- `xfs/xfs_mxfs_dlm.c::mxfs_ag_dlm_unlock` — added a per-AG inode-buffer
  delwri drain after the existing alloc_buflist drain.  Walks
  `pag->pag_bcache` for inode cluster buffers with `b_li_list` non-empty
  and not on a delwri queue, queues them via `xfs_buf_delwri_queue`, and
  submits synchronously via `xfs_buf_delwri_submit + blkdev_issue_flush`.
  This drains pending iflushes so when we release the AG DLM the home
  block on disk reflects all our latest changes.
- `xfs/xfs_mxfs_dlm.c::mxfs_dlm_invalidate_ag_meta` — added P7-INSTR
  pr_warn for skipped inode buffers (kept for diagnostic continuity).
- `xfs/xfs_icache.c::xfs_iget_check_free_state` — added P7-INSTR pr_warn
  dumping the buffer state when the corruption check fires.
- `VERSION` — 0.2.7 → 0.2.9.

## Files modified in v0.2.7

- `xfs/libxfs/xfs_ag.h` — added `pag_dlm_acquire_lock` (struct mutex) to
  `xfs_perag` to serialize CAW acquires without holding `pag_dlm_lock`.
- `xfs/libxfs/xfs_ag.c::xfs_initialize_perag` — `mutex_init` for the new
  field.
- `xfs/xfs_mxfs_dlm.c::mxfs_ag_dlm_lock` — restructured to:
  1. Take `pag_dlm_lock` briefly for the fast paths (nested re-acquire OR
     cancel-deferred-release); both return without ever touching
     `pag_dlm_acquire_lock`.
  2. Drop `pag_dlm_lock`.
  3. Take `pag_dlm_acquire_lock` (serializes concurrent fresh-acquires on
     this node).
  4. Re-check state under `pag_dlm_lock` and re-take fast paths if state
     changed while we waited on `pag_dlm_acquire_lock`.
  5. Drop `pag_dlm_lock`.  Call `mxfs_v5_dlm_ag_lock` (CAW) holding only
     `pag_dlm_acquire_lock` — never `pag_dlm_lock`.
  6. Take `pag_dlm_lock`, set `holders=1`, drop both locks.
  7. `mxfs_dlm_invalidate_ag_meta(pag)` outside both locks.
- `VERSION` — 0.2.6 → 0.2.7.

## Why this can't deadlock with iodone any more

`mxfs_dlm_ag_meta_iodone` only ever takes `pag_dlm_lock`, never
`pag_dlm_acquire_lock`.  After the fix, no thread holds `pag_dlm_lock`
across a CAW round-trip.  Iodone can therefore always make progress —
decrement the counter, fire the deferred `mxfs_v5_dlm_ag_unlock` when the
counter drains — even while another thread on this node is blocked in a
multi-second CAW poll loop.

## Remaining issues (next session)

1. **`Free inode 0x%x not marked free!` on cross-node iter-3+ stress** —
   *DIAGNOSED, fix in v0.2.8*.  Instrumentation (P7-INSTR) confirms every
   skipped invalidate is for `blkno=128` (the root-dir's inode cluster) with
   `bli=NULL, dq=0, b_li_list non-empty`.  The b_li_list contains pending
   inode log items from iflushes that haven't completed writeback.  As long
   as our node has any pending iflush in the cluster, the v0.2.6 invalidate
   filter (correctly) refuses to stale it — staling would discard our
   un-written changes.  But peer modifications to *other* inodes in the
   *same* cluster aren't visible to us.  Result: T1's `xfs_iget_check_free_state`
   reads stale `i_mode != 0` for an inode that the peer (T2) actually freed,
   trips the corruption check.  **v0.2.8 fix**: extend `mxfs_ag_dlm_unlock`
   to sync-flush inode buffers in this AG with non-empty `b_li_list` via
   `xfs_buf_delwri_queue` + `xfs_buf_delwri_submit` before peer can acquire.
   This drains pending iflushes for the AG so the home-block reflects all
   our changes.  When peer modifies and we re-acquire, our cached buffers
   have empty `b_li_list` and the invalidate stales them, forcing a fresh
   re-read.
2. **`Metadata has LSN (1:178) ahead of current LSN (1:2)`.**  T1's local log
   LSN is far behind T2's, but T1 reads a buffer with T2's LSN stamped on it;
   subsequent write attempts trip the LSN check.  Per-node logs + shared
   metadata buffers fundamentally fight here.  mxfs.1's solution to this
   needs to be ported.
3. **Slow T2 dd in iter 1 (24 MB/s vs T1's 285 MB/s) and intermittent slowness
   on later iters.**  Symptom of frequent BAST handoffs and AG-DLM contention.
   Once correctness is solid, performance work is needed.
