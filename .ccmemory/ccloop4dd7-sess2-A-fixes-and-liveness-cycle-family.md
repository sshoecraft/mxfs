---
name: ccloop4dd7-sess2-A-fixes-and-liveness-cycle-family
description: sess2: 3 corruption fixes landed+firing (P116 handoff-adopt, SETSIZE/IFREE revalidate); remaining killer = cross-node inode↔AG DLM deadlock family (3…
metadata:
  type: project
---

# ccloop-4dd7 sess2 — corruption fixes landed; liveness cycle family = the wall

## Fixes landed this session (v0.11.47→49, build 28F457A5, all uncommitted)
1. **P116 handoff-adopt arm** (xfs_mxfs_dlm.c ~18102): zombie keep was handoff-blind — peer
   realloc(random gen)+free defeats the gen+1 arm. Now: clean+!unpublished && (grant-handoff-bit
   || gen+1) → adopt freed image. PROVEN ROOT via ino 2097290 (P-DIFREE-DBL agno=1 agino=138:
   P144/P150 braid fully coherent; divergence was the zombie's phantom life, NOT buffer staleness).
   FIRING: P116-ZOMBIE-ADOPT handoff=1 rescues (ino 2097287 gens unrelated 1775251766 vs 429673170).
2. **SETSIZE-REVALIDATE-MISS** (pal/linux/xfs_iops.c xfs_setattr_size after ilock EXCL): reload at
   EX acquire can flip incarnation (file→dir P-RELOAD-TYPEFLIP, or mode=0 zombie-adopt); truncate
   then walked LOCAL-format dir fork → !xfs_ifork_has_extents internal error → shutdown. Now clean
   -ESTALE before ijoin (VFS retries with LOOKUP_REVAL). FIRING+rescuing (ino 139 mode=040755, 133/136 mode=00).
3. **IFREE-REVALIDATE-SKIP** (xfs_inode.c xfs_inactive_ifree after xfs_ilock): peer freed the ino
   mid-inactivation (BAST forced our EX out during truncate phase; fresh EX at ifree reload-adopts
   mode=0) → difree double-free + P71 agi-unlinked-garbage (empty bucket) → -117. Now: mode==0 →
   forget in-core unlinked membership (i_next=NULLAGINO, i_prev=0, clear MXFS_IF_LOCAL_UNLINK),
   cancel clean trans, return 0. PROVEN via ino 10485889 autopsy.
4. **xfs_lock_two_inodes ABBA breaker** (xfs_inode.c + i_dlm_tries* fields in xfs_inode.h +
   bounded path in mxfs_dlm_inode_lock_routed + P-ABBA-BOUNDED-TIMEOUT bail in ilock_begin):
   second-inode DLM acquire bounded 3 tries; on timeout drop first grant-hold, jitter backoff,
   retry. Uses existing mxfs_v5_dlm_inode_lock_retries. NOT YET OBSERVED FIRING (cycle moved).

## THE WALL — cross-node cluster-lock cycle family (RULE-6 OPEN, GPT consult launched)
Three stack-proven shapes, all ~180s acquire-timeout → -110 → force shutdown BOTH nodes:
- S1: n2.rm holds dir131-grant (lock_two m0) wants file-B; n1 holds file-B (holder blocked
  elsewhere), wants dir131. 184s. (Fix 4 covers the lock_two edge only.)
- S2: same via setattr_size/do_truncate chains.
- S3 (BOTH EDGES DIRTY — unbreakable at deadlock time): n1 xfs_create holds dir131-EX + AG-X-EX,
  trans dirty (dialloc logged inobt), blocked at icreate→iget(child ino 139) EX; n2 holds 139
  ILOCK-EX in dirty truncate, blocked at __xfs_free_extent→mxfs_ag_dlm_lock(AG-X). Upstream
  order truncate=ino→AG vs create=AG→child-ino is inherent. 139 was LIVE on n2 while n1's
  dialloc picked it (divergent inobt copies transiently, or n1's create raced n2's unpublished).
- P36-STRIKEOUT then starvation: after dwork strikeout, deferred BAST re-arm relies on
  ilock_end/fresh notify; blocked-holder case never fires them.
- Candidate designs in the GPT prompt: A=dialloc-time bounded child pre-acquire before inobt RMW
  (kills S3 back-edge fail-fast while clean); C=master-side wait-for-graph deadlock detection with
  clean-waiter victim; E=timeout policy (release cached grants + EAGAIN when clean). My ranking A>E>C.

## Env notes
- Repro: N1=test1 N2=test2 MXFS_PASS=/tmp/.mxfs_pass scripts/agi_wedge_repro.sh 180 24.
  WATCH WINDOW BUG: checker ends at DUR+8s; the 11:53:44 shutdown escaped a "no escalation"
  verdict (round launched ~11:50:35). Always verify logs, not the exit banner.
- scripts/abba_stack_capture.sh (storm-triggered stack dumps both nodes, repeats while storm lasts).
- scripts/p144_join.sh <logdir> <daddr>: cross-node WR/RD crc join (proved cold reads always FRESH).
- P150 cap 20000/boot exhausts mid-round under churn; raise if record-level evidence needed late.
- prep_cluster ~55s; VM dmesg replays prior rounds — filter by round window timestamps.
