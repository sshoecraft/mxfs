---
name: sess7-part3-AG-convoy-design-constraint
description: sess7 part3: AG convoy PROVEN (rm dirty-trans holds AG-4 waits AG-0, P1-AGWAIT trans_held_ags probe, build 20CD7654). Splice-removal FORBIDDEN: EFI-o…
metadata:
  type: project
---

# sess7 part 3 — AG convoy: proven shape + the design constraint on the fix

## PROVEN (run97, build 20CD7654, dlm_fairness 3/8)
New probe `mxfs_fmt_trans_held_ags` (xfs_mxfs_dlm.c, prints the trans's t_mxfs_ag_unlocks agnos in P1-AGWAIT):
- test8: `P1-AGWAIT ag=0 comm=rm pid=1138 trans_dirty=1 trans_held_ags=[4,]` — a DIRTY rm trans holds AG-4's DLM grant while BLOCKING on AG-0 (descending!).
- test3: `P1-AGWAIT ag=3 comm=rm trans_dirty=1 trans_held_ags=[7,]`.
- mv waits show `trans_held_ags=[]` (benign).
Cross-node hold-and-wait convoy; broken only by ~1s retries/120s timeouts; a defer-finish victim dies rc=-110 → shutdown (run96 test4 @273; "Corruption of in-memory data (0x8) at xfs_defer_finish_noroll" = the lock-timeout ERROR PATH, not real corruption). Fs-shutdown node then keeps its DLM grants (zombie wedges the cluster — SEPARATE liveness gap worth fixing: surrender all grants on xfs_force_shutdown).

## THE CONSTRAINT (do NOT just remove the dup splice!)
xfs_trans.c ~175-192: `list_splice_init(&tp->t_mxfs_ag_unlocks, &ntp->…)` at xfs_trans_dup was itself a PROVEN FIX: "if the new tp's defer iteration processes a pending EFI from a prior sub-trans, the EFI's (bno,len) may now overlap blocks the peer already freed → 'ltbno+ltlen > bno' corruption (line 2106). The defer chain semantically owns the AG-DLM grant for its entire lifetime, mirroring how xfs holds the AGF buf across rolls." Removing it reintroduces the EFI-overlap double-free. (Inode unlocks deliberately do NOT migrate — v0.3.106 attempt-1 lesson.)

## Fix-shape options for next session (in preference order)
1. **Ascending-only acquisition discipline**: upstream sorts extfree work items by AG ascending per roll (~/src/linux fs/xfs/xfs_extfree_item.c:382-431 `xfs_extent_free_diff_items`+list_sort — check our fork has it) and enforces t_highest_agno for allocations. The convoy pairs observed are DESCENDING acquisitions (hold 4 wait 0; hold 7 wait 3). Find which defer path acquires descending (cross-TYPE sequences: ifree (AGI in inode's AG) after extent-free (AGF in data AG), etc.) and enforce/sort. If a descending need is unavoidable in one chain, pre-acquire ALL needed AGs ascending up-front... needs the AG set known early (it isn't, defers discover late).
2. **Per-AG retention only while pending items reference that AG**: at each roll, release grants for AGs with NO remaining defer work items (walk tp->t_dfops pendings by group), keep those still referenced. Preserves the EFI guard exactly; shrinks hold windows to actual need.
3. **Deadlock-breaker at the wait**: when blocking descending (wanted_agno < any held agno) with a DIRTY trans, cap the wait (e.g. 10s) then... nothing safe to do (can't release dirty) — only detect+shout. Not a fix; combine with 1/2.

## Current build state
- 20CD7654 = CAE7BFBD (FIX-16..19) + FIX-20b (phantom reconcile: strike detector + P6Z send, fields i_dlm_phantom_bast_j/_n + i_dlm_reconcile_pending) + pace levers (P44 cap 2000, leafprobe default 0, P60 FUA-compare instr-gated) + P1-AGWAIT held-set probe. Deployed on the cluster (run97).
- xfs_trans.c UNMODIFIED (the Edit was aborted on the read-first check — verified constraint first).
- run97: dlm_fairness 3/8 (the convoy) — the reproducer is `./run.sh 8 tcp dlm_fairness` after a clean cycle, ~3 min.

## Ladder state vs criteria (full suite × 1/2/4/8)
- 8/tcp standalone dir_reuse: PASS 8/8 (run93). 8/tcp full suite best: 13/17 (run94). Open blockers: dlm_fairness/tcp_dlm_scaling (THIS convoy), dir_reuse in-suite pace (probably improves with the pace levers + convoy fix — unmeasured), soak (fallout only). 1/2/4 unmeasured this generation.
