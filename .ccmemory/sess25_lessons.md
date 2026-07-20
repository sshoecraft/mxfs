---
name: Sess25 lessons
description: Sess25 (2026-05-05) — v0.3.86 single→multi transition fix + v0.3.87 VFS i_size sync ENABLE cross-node coordination (was completely broken at sess24 end). bnobt LEFT/RIGHT-FAIL persists as timing-sensitive steady-state divergence. P39 trace + drain_meta_buffers hypothesis for sess26.
type: project
originSessionId: df4652e1-59db-47e6-a56f-a61c4a264eef
---
# Sess25 (2026-05-05) — MXFS bnobt+ModeA investigation

## What was tried

### v0.3.84 — dir-block stale in mxfs_dlm_bast_process (KEPT)
- Added P36-INSTR + walk dir inode extents (EXTENTS-format only) and
  stale cached dir block bufs in pag_bcache via xfs_buf_incore +
  xfs_buf_stale.
- Targets sess24 finding: `mxfs_buf_is_ag_metadata` doesn't cover
  dir3 buf_ops (data/block/leaf/leafn/free), and FUA hook is scoped
  to AG-meta only.
- Stress 15×512 with this fix: iter 2 + iter 4 LEFT-FAIL — within
  sess24 baseline. Not a regression.
- **P36 NEVER fires in stress** because root dir stays LOCAL format
  throughout these workloads. Code is zero-cost for stress and
  unverified for Mode A scenario.

### v0.3.85 — caw "already_held" compat check (KEPT)
- In `mxfs_dlm_caw_lock` when `our_mode == mode`, additionally
  check `compatible_excluding_self`. If peer holds incompatible,
  clear our bit via CAW + untrack + retry.
- Target: OR-bug from sess24 hypothesis where flush_held_to_disk
  unconditionally OR's holder bits.
- **P37 fires ZERO times in stress** — divergence is NOT both-bits-set.
  Defensive safety net only.

### v0.3.86 — periodic-verify fast-path forced slow-path (REVERTED)
- Every Nth fast-path AG-DLM acquire forced to slow-path so
  invalidate_ag_meta refreshes bufs and v0.3.85 compat check fires.
- **T2 xfsaild kthread CRASHED at iter 3** with WARN at
  `kernel/exit.c:821` (do_exit, make_task_dead).
- **Cause**: invalidate_ag_meta is destructive when WE legitimately
  hold the grant. Stales bufs that may be in xfsaild's flush window.
  Normal slow-path runs invalidate AFTER bast_work_fn drained
  (Phase-2b drain_meta_buffers); periodic-verify skipped that.
- **Don't repeat without first draining or signaling
  same-holder-reacquire to skip invalidate.**

## NEW root-cause finding — single→multi transition bug

After fresh `mxfs_cluster_reset.sh`, **T2 cannot see directories T1
created**: ls shows `d?????????` (entry exists, stat fails);
cat returns ENOENT even after sync+drop_caches; T2 has zero
bast_notify events post-mount.

Mechanism:
- T1 mount in single_node: caw_lock takes the single_node fast-path,
  calls `mem_lock_track` (in-memory only, NO disk slot write).
- xfs side sets `i_dlm_mode=EX` cached.
- T2 mount, same.
- Discovery → both transition.
- `mxfs_dlm_caw_set_single_node(false)` calls
  `mxfs_dlm_caw_flush_held_to_disk` which **unconditionally OR's
  holder bits** into disk slots via find_slot+CAW.
- T1 writes its EX bit. T2 (later) finds slot with T1's bit, OR's its
  EX bit. Slot has BOTH T1+T2 EX bits.
- caw_lock's "already_held" check sees our bit → returns success
  without conflict detection.
- xfs side has cached i_dlm_mode=EX, fast-paths. caw never reached.
- Both nodes proceed without coordination.

`mxfs_dlm_peer_joined_flush` (xfs side) does flush data +
invalidate AG-meta bufs but does NOT invalidate i_dlm_mode cached
state on inodes nor `pag_dlm_cached` on perags. The cache survives
the transition.

This explains sess24's P35 finding ("both pag_dlm_cached=true on
AG=0 for 50s without coordination"). Same root cause.

Stress sometimes "works" early because xfs_inode evictions reset
the cached state, forcing slow-path through caw. AG-DLM has the
SAME bug but `pag_dlm_cached` doesn't get evicted, so divergence
persists for AG=0.

## Sess25 IMPLEMENTED fixes (v0.3.86 + v0.3.87)

### v0.3.86 — single→multi transition fix (KEPT)
- caw `flush_held_to_disk`: don't OR holder bits to disk; just clear
  mem_locks. Disk slots stay empty post-transition.
- xfs `peer_joined_flush`: walk `pag_ici_root` radix tree per
  perag; force `i_dlm_mode=NL`, `i_dlm_state=NONE`, `i_dlm_stale=true`
  on cached inodes (when no holders + not demoting); force
  `pag_dlm_cached=false` (when no holders).

### v0.3.87 — VFS i_size sync after reload (KEPT)
- `mxfs_dlm_reload_inode` now `i_size_write(VFS_I(ip),
  ip->i_disk_size)` after `xfs_inode_from_disk`.
- Without this, reload picks up disk content but VFS layer's
  `inode->i_size` stays at old value → vfs_read returns
  truncated/empty content despite correct xfs ip state.

### Validated outcomes
- Cross-node read-after-write WORKS: T1 echo > foo + T2 cat foo
  returns correct content + size.
- Cross-node directory visibility WORKS: T1 mkdir d + T2 ls /
  shows d (was `d?????????`).
- 5×64MB stress passes 5/5 iters (first observed full pass at
  sufficient size).  5×128MB also passes 5/5.
- 5×256MB fails iter 3 with bnobt LEFT-FAIL — residual bug.
- 15×512MB fails iter 3 with fdatasync CAW timeout — new deadlock.

### v0.3.99 — XBF_DONE clear in invalidate_ag_meta (KEPT)
- Comment in `mxfs_dlm_reload_inode` says "Staling the buffer clears
  XBF_DONE" but actual `xfs_buf_stale` only sets XBF_STALE and clears
  `_XBF_DELWRI_Q`.  XBF_DONE remains.
- Without explicit clear, subsequent `xfs_buf_get` may reuse the
  staled buf without re-reading from disk.  Peer's mods missed →
  bnobt LEFT/RIGHT-FAIL.
- Fix: `bp->b_flags &= ~XBF_DONE` after `xfs_buf_stale(bp)` in
  `mxfs_dlm_invalidate_ag_meta`.  Force-clear matches documented intent.
- Variance still exists; not 100% deterministic.

### v0.3.95 — bnobt LEFT/RIGHT-FAIL partial fix (KEPT)
- **Root cause identified**: `xfs_log_force(mp, XFS_LOG_SYNC)`
  returns BEFORE `xlog_ioend_work` fires (on
  `mp->m_log->l_ioend_workqueue`).  `xlog_ioend_work` is what runs
  `xlog_cil_committed → xlog_cil_ail_insert` to move items to AIL.
  If drain runs in this gap, items still in CIL are missed.  Disk
  doesn't get them.  Peer reads stale → bnobt LEFT/RIGHT-FAIL.
- **v0.3.95 fix**: in `mxfs_dlm_ag_bast_work_fn` Phase-2, before
  `drain_meta_buffers`: `msleep(3) + xfs_log_force(SYNC)`.  msleep
  gives async work time, second log_force catches new items.
- Empirical, variance remains.  Sess26 should implement proper
  completion sync.
- 5×256 PASSES 5/5 in best run.  15×256 variance: 1-9 iters.

### v0.3.96-97 — bnobt fix attempts that DIDN'T work
- v0.3.96 flush_workqueue(l_ioend_workqueue): doesn't catch items
  queued during the flush.  Regression.
- v0.3.97 polling drain loop: cumulative delays cause regressions.
- v0.3.93 force-drain all XBF_DONE bufs: iunlink corruption.
- v0.3.89-92 various BLI/FUA skip variants: P42 fired 0 times,
  not the right angle.

### v0.3.88 — Mode A fix (KEPT)
- Added dcache invalidation in `mxfs_dlm_reload_inode` for dir inodes.
- `d_find_alias(VFS_I(ip)) → shrink_dcache_parent → dput`.
- Mode A root cause: peer-modified dir entries reloaded into xfs ip,
  but VFS dcache stays stale.  Subsequent `rm name` hits dcache, finds
  stale child dentry → iget(stale-inode) → xfs_dir_removename iterates
  freshly-reloaded (now-empty) dir → ENOENT.
- Reproduced cleanly at sess25 (15×256 iter-2 with v0.3.87+P39+P40).
- After fix: 15×256 iter 1+2 PASS, fails iter 3 (run 1) or iter 8
  (run 2) with bnobt LEFT-FAIL — significantly better than sess24
  baseline iter 2-4.  Mode A no longer fires.

### NEW failure mode at sess25 end
- 15×512 stress: BOTH nodes' fdatasync timeout simultaneously at
  iter 3 with `Connection timed out` (CAW grant 120s).
- Genuine cluster deadlock — exposed only because v0.3.86+87 made
  coordination actually work.
- Sess26 priority-1 to investigate.

## Sess26 priorities

1. **Iter-3 fdatasync deadlock** — new failure mode exposed. BAST
   chain circular wait? cross-AG ail_push_all_sync (similar to
   sess18 v0.3.24 issue)? Diagnose with stats + wchan/stack at
   timeout.
2. **bnobt LEFT/RIGHT-FAIL residual** — still fires in 5×16 iter 4.
   Now diagnose-able with real coordination.
3. **Mode A validation** — v0.3.84 P36 didn't fire; construct
   EXTENTS-format dir workload.

## Don't repeat (sess25)

- Periodic-verify forced slow-path that calls `invalidate_ag_meta`
  while we still hold the grant — xfsaild crash.
- Building Mode A reproducer that doesn't push dir to EXTENTS
  format (LOCAL format dirs go through reload_inode, not the
  bast_process dir-block stale path).

## Useful diagnostics added this session

- **P36-INSTR**: `mxfs: P36-INSTR ino=%llu BAST-DIR-STALE ext=%u
  dirblks=%u cached=%u staled=%u skip_locked=%u` — fires only when
  BAST processes a dir inode in EXTENTS format. Dormant under
  LOCAL-format-dir workloads.
- **P37-INSTR**: `mxfs: P37-INSTR caw-divergence ag=%u retry=%d
  our_mode=%u peer-incompat cas_rc=%d ...` — fires when caw
  detects our bit + peer incompatible bit in same slot. Dormant
  in normal stress (didn't hit OR-bug variant).
