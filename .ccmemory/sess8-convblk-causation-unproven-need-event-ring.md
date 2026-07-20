---
name: sess8-convblk-causation-unproven-need-event-ring
description: sess8 update: convblk-removal path IS exercised but causation unproven (slow-path EX always reloads); printk EX-overlap check defeated by dmesg-roll…
metadata:
  type: project
---

## Caveat on [[sess8-CONFIRMED-root-convblk-removal-double-grant]] — causation NOT proven.

Two findings this session temper the "convblk-removal is THE root" conclusion:

1. **The slow-path EX acquire ALWAYS reloads** (xfs_mxfs_dlm.c ~7055 `i_dlm_stale=true` + ~7079
   `mxfs_dlm_reload_inode(...,true)` for any populated inode). A PR→EX upgrade FAILS the fast-path
   gate (~6336: needs i_dlm_mode>=req) → takes the slow path → reloads. So a node PROMOTED to EX
   after the convblk removal DOES reload the peer's durable image before modifying. The
   convblk-removal therefore may NOT directly cause a write-clobber by the promoted node — the
   residual vector may instead be a stale READ via node A's STILL-CACHED PR (i_dlm_mode=PR retained
   locally after the master silently removed A's entry) on a concurrent readdir/lookup fast-path
   (~6337: mode==PR && i_dlm_mode==PR → reads cached fork, no reload), while node B holds EX.

2. **EX-overlap check was INCONCLUSIVE**: reproduced dlm_fairness fail (iter 9, dirwr=1), extracted
   P106-EXGRANT/EXREL for dir ino=131 both nodes — showed a ~6.1s apparent test1 EX-hold with no
   test2 overlap, BUT under dirwr=1 the dmesg ring ROLLS (heavy logging) and P106 are plain pr_warn
   (not ring-buffered elsewhere), so intermediate GRANT/REL pairs are LOST → cannot confirm/refute
   overlap. This re-confirms the prior-session conclusion: **printk-based tracing cannot catch this;
   a LOCK-FREE PER-CPU EVENT RING (no printk in hot path), dumped only at the leftover, is REQUIRED.**

## Leftover pattern this session: `n1_r1.done` + `n2_r7.done` (rename TARGETs), SYMMETRIC on BOTH
nodes — each node's own `rm <x>.done` was durably reverted by the peer's stale-base RMW. So the
clobber is mutual/symmetric, consistent with concurrent divergent-base RMW.

## NEXT SESSION PLAN (full budget):
1. Build a lock-free per-CPU event ring in dlm/dlm.c + xfs_mxfs_dlm.c recording {realns, node,
   ino, op∈{REQ,GRANT,REAFFIRM,RELEASE,REMOVE,CONVBLK,EX-ACQ,EX-REL,RELOAD,RMW-COMMIT}, mode, gen}.
   Dump BOTH nodes' rings (no printk in hot path; copy to a /proc or trigger-file on a detected
   leftover or at unmount). Correlate by realns to find the exact window two nodes mutate ino=131
   from divergent bases.
2. Test the cheap hypothesis-2 fix FIRST (low risk): when the master removes/downgrades a node's
   GRANTED entry (convblk branch, dlm.c ~2229), also force that node to drop its CACHED dir lock
   (i_dlm_mode→NL, i_dlm_stale=true) so a concurrent reader on it can't use the stale cached PR. For
   the LOCAL sender set it directly; for a REMOTE sender, the master must send a demote/BAST.
3. If the ring proves true EX-overlap (double-grant), implement convblk option B (keep holder entry
   visible; break the PR→EX conversion deadlock explicitly).

## DEPLOYED = AFD6B76A06125A24489A130 (rename guard KEEP + P-SFREL + P-CONVBLK-REMOVE markers).
Reliably 15/16, no shutdown cascade. Marker NOT written (criterion 16/16 unmet).
</body>
