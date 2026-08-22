---
name: ccloop-c7ee71c6-sess212-nearmiss-benign-class-477-fence-scoped-latch
description: sess212: near-miss = benign LISTDRAIN-repairable BUF class (5-node fence chain, NOT arm A); 0.11.477 fence-scoped probe latch; full board 27/27 PASS
metadata:
  type: project
---

# sess212 — near-miss classified benign; 0.11.477 fence-scoped latch

## Near-miss analysis (sess211's 16:48Z event) — NOT arm A
- The 16:48:16-24Z burst hit FIVE nodes (test14/15/29/31/32), a cascading chain
  of no-inode release fences: fence inos chain node-to-node
  63452031→29897597→17314685→53491136→33554595.
- Each node stalled ~2s at stall==2 on its OWN local inode-cluster BUF
  (bflags 0x500020, pin=0) parked on pag_mxfs_alloc_buflist — the documented
  _XBF_DELWRI_Q/_XBF_MXFS_ALLOC_QUEUED design tension (xfsaild can't write it).
- P-NOINO-LISTDRAIN (stall==3 repair) fired and CLEARED it (test31 16:48:24;
  next fence wait 923ms). Zero DRAIN-STUCK, zero shutdowns fleet-wide.
- Post-latch P129-CLSKIP = healthy pattern only: IFLUSH_RAN ili_fields=0,
  transient ILOCK_NOWAIT_FAIL owned by live mkdir resolving to IPUSH err=0 <1s.
- Contrast with incident474 arm A: INODE log item frozen, ILOCK owner blocked
  in DLM (ifree-after-BAST-release / b4_noauth hole) — LISTDRAIN cannot repair
  that class. Discriminator: P-AILMIN item type BUF (benign) vs INODE (arm A).

## Probe latch was accumulating fleet-wide — fixed in 0.11.477
- The stall==2 self-latch was PERMANENT; benign bursts latched 9/32 nodes
  within a day of .476 (~1450 P129 lines/node per 12-lap batch). test2 latched
  17:01:26Z with NO surviving P-AILMIN line (ratelimit) — latches can be
  invisible in klog.
- 0.11.477 (sv 79342FFAD37A8568EB0B033): mxfs_ailstuck_probe_fence_arm/disarm
  in xfs_trans_priv.h + mxfs_ailstuck_fence_armers (xfs_trans_ail.c). Fence
  arms with probe value 2 + refcount; disarms on fence success returns AND on
  min-advance (fresh odumps budget for a second freeze in the same fence).
  DRAIN-STUCK/shutdown exits deliberately never decrement → latch persists for
  post-mortem. cmpxchg(2→0) never clears manual param arm (1) or the 30s
  xfs_ail_push_all_sync latch (1).

## Verification
- 12/12 rsync_paired laps PASS on .476 (13-17s/60s) pre-rebuild.
- 0.11.477 deployed via prep_cluster (73s, all 32 converged); FULL board
  27/27 real PASS at 32/caw (17:36-17:46Z run_ids), open_defects POLICY-red
  (30 open). Full board doesn't fit one 590s foreground call — ran in 4
  explicit-test chunks after the initial default run recorded 15.

## Next
- Keep lapping rsync_paired for an arm-A recurrence (INODE-item P-AILMIN or
  DRAIN-STUCK). On decisive P129 evidence → RULE-5 consult on fix design.
- Then resume #18 P95-NL-UNDER-HOLD.
