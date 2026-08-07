---
name: ccloop-c7ee71c6-sess47-TAIL3-379-direction-refinement
description: sess47 FINAL: 0.11.380 fleet = dirty-discriminated AGI revalidation (storm 584→0 new fires through full matrix; repro CLEAN; matrix 9/9). Rig green a…
metadata:
  type: project
---

# 0.11.380 (7BF4FECC79FBEAD1ECCF0DC) — DEPLOYED FLEET-WIDE, sess47 true end

## What 380 adds over 379
xfs_inactive_ifree revalidation now DISCRIMINATES divergence direction: differs && (AGI bli-dirty || pinned || DELWRI || uncheckpointed) ⇒ WE own the delta ⇒ trust IN-CORE (ck_differs forced 0); differs && clean ⇒ prior-tenure fossil ⇒ trust DISK (the test32 fix). P-IFR-AGI-STALE capped at 100, prints only the clean-but-divergent (true stale) direction.

## Verification on deploy
- reap_midlist_repro: CLEAN both scenarios.
- openunlink_matrix: 9/9.
- Fire-rate: test1 count UNCHANGED (584 pre-380 relics; ZERO new fires through a full matrix) ⇒ the 379 storm was entirely the dirty-direction case, now silent and correctly handled; true staleness is rare as expected.

## Relay queue (priority order)
1. Aged soak on 380 (lap → idle-gap → lap → matrix → 4-signal sweep: P-IFR-AGI-STALE / P71-INSTR / P-PINNED-REREAD / P53 pairs + shutdowns). Promote the test32-variant closure only after the variant's natural window (matrix reuse churn) stays clean repeatedly.
2. Finding B: foreign-zombie authority guards (lu=0/au=0/ub=-1 reached destructive inactivation — audit the B1-B4 disk-mode read path for the same stale-buffer exposure).
3. Fossil-producer delwri-window hunt (…-ADDENDUM-fence-ran-and-failed): P-PINNED-REREAD delwri arm live, 0 false positives — a fire names the culprit stack.
4. icluster campaign (GPT items 2-4, default-ON), FOREIGN-REPLAY, TCP arm.

Rig at handoff: 0.11.380, 32/32 mounted, ship config (icluster_dlm=0, open_tracking=1, inocl_fence=1), board green, all rings preserved (test2 ×2, test9, test10, test32).
