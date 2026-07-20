---
name: sess34-GPT-plan-dlm-acquire-boundary-coherency-and-prompt-bast
description: sess34 GPT-5.5 plan for dir_reuse 2/tcp: SLOWNESS=prompt BAST honor + acquire dir-EX-direct + event-driven waits; CORRECTNESS=invalidate whole dir fo…
metadata:
  type: project
---

## sess34 — GPT-5.5 architectural plan for dir_reuse_coherency 2/tcp (the ONLY 2/tcp blocker)

Diagnosis it's based on: [[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]] (slowness) +
[[sess34-dirreuse-acquire-side-stale-rmw-trylock-skip]] (correctness). Implement INCREMENTALLY
(RULE 4: one change, build, run ×3-5 for variance, measure). Keep the other 16/17 2/tcp tests green.

### SLOWNESS fixes (the ~6s dir-EX handoff = MXFS_LOCK_ACQUIRE_WAIT_MS=6000 grant timeout):
1. **Make "revoke pending" ORTHOGONAL to ISTATE_ACQUIRING.** A peer BAST must set a revoke_pending
   flag honored REGARDLESS of state — today the ACQUIRING branch only sets i_dlm_stale (xfs_mxfs_dlm.c
   :5482-5489) and it's honored only by the in-flight acquire's post-publish, so under mutual 2-node
   EX contention nothing drives the revoke until the 6000ms timeout.
2. **ilock_end must honor revoke_pending, NOT only state==MXFS_DLM_ISTATE_BAST** (currently
   xfs_mxfs_dlm.c:8972 gates on state==BAST). Queue bast_process when last holder drops & revoke
   pending.
3. **Bounded fairness window** (min-hold ~1-5ms + max-hold-after-BAST ~5-20ms or max-ops 8-32) so a
   freshly-granted holder makes a little progress before yielding — avoids ping-pong thrash. (MHT=50
   alone didn't help because it isn't the limiter; the limiter is the 6000ms grant timeout.)
4. **Acquire the PARENT DIR DLM in EX DIRECTLY for modify ops** (create/unlink/rename/mkdir/rmdir/
   link/symlink) instead of PR-for-pathwalk-then-upgrade-to-EX. This kills the PR→EX conversion
   deadlocks (P-CONVBLK-DENY ~80/run → EDEADLK → drop-to-NL+reacquire = expensive). HIGH-VALUE.
5. **Replace 3×6000ms acquire retries (xfs_mxfs_dlm.c:8652) with EVENT-DRIVEN waits**: wake on
   grant-arrived / revoke_pending / holders==0 / unlock-done with ~20ms granularity; keep a SEPARATE
   long liveness watchdog (30-120s) for true no-progress. Do NOT just shrink MXFS_LOCK_ACQUIRE_WAIT_MS
   (3 attempts then FORCE-SHUTDOWN at 8720 → would convert contention into shutdowns).

### CORRECTNESS fixes (acquire-side stale dir DATA/LEAF block RMW; trylock-skip serves stale):
6. **Move dir-block invalidation from read-time (xfs_da_read_buf XBF_TRYLOCK-skip, racy) to the DLM
   ACQUIRE boundary** — after a FRESH PR/EX grant, BEFORE publishing/admitting local users and before
   any RMW, when no XFS txn/ilock is held yet so a BLOCKING buf lock is safe. Walk the WHOLE dir data
   fork (data+leaf+free blocks, not just block 0) and invalidate stale incore buffers.
7. **Remove the XBF_TRYLOCK skip as a correctness mechanism**; in xfs_da_read_buf, a stale buffer
   found post-acquire-revalidation = hard restart(-EAGAIN to a safe point)/assert, not silent serve.
8. **Tag dir buffers {fsid, ino, di_gen, fork, dabno, dlm_epoch}**; stale if any differ or
   buf_epoch < inode dlm_epoch. Fixes ABA: same-ino-number reuse (di_gen differs) AND same-daddr
   reuse (owner differs). Also retag on NEW dir-block alloc/init so an old XBF_DONE buf at a reused
   daddr is never read as valid.
9. **Make the AIL keep-guard (sess43, xfs_da_btree.c:3210) GENERATION-AWARE** — never preserve an
   old-dlm-epoch buffer as valid-for-RMW. Release side must flush+wait so no old-gen dirty/in-AIL
   dir metadata survives (Invariant 1 truly holds), so acquire side can invalidate freely.
10. Consider DLM resource key = fsid+ino+di_gen (incarnation) so cached per-inode DLM state can't
    cover a reused inode incarnation.

### Build/probe state (build BDD203F2): P34-ACQ-SLOW + P34-LEAF-DRAIN + P34-TRYLOCK-STALE +
DRCph markers all in tree (keep — useful). reset2.sh before EVERY run; dmesg ring WRAPS; run 3-5×
(extreme variance: timeout/readdir-short/leaf-hole). Cluster left mounted on BDD203F2 (next session
reset2 first). Marker NOT written.</body>
