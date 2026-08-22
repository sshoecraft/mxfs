---
name: ccloop-c7ee71c6-sess390-end-state-0.21.4-board-clean
description: sess390 END: rig 64 AGs on 0.21.4 sv DFB4C46B445E6BBF308BEA1 (requeue=1, readopt window -1 inert); 64-AG board every criterion passed; 25-AG correctn…
metadata:
  type: project
tags: [sess390, end-state, 0.21.4, board, handoff]
---

# sess390 end state (ccloop c7ee71c6)

## Builds this session
0.20.1 convoy-aware noino fence; 0.20.2 nonblock AG acquire -EAGAIN in demote window; 0.21.0 lifecycle probe+requeue (knob) + readopt gate (knob); 0.21.1 requeue default 1; 0.21.2 pinned re-adopt; 0.21.3 RESOURCE_FREE class; 0.21.4 drop the resfree WARN (kernel_health). Rig: 32/caw, 64 AGs, 0.21.4 sv DFB4C46B445E6BBF308BEA1, all 32 mounted.

## Verified
- 25 AGs (agcount<nodes): 0.20.2+ = 0 relfence wedge / 0 shutdown / 0 split-under-protest / 0 dirty-cancel across 3+3+4 laps (was: 2 wedges + 24 splits on 0.20.0/0.20.1). Pace at 25 AGs still fails (PACE-388).
- 64 AGs: full board on 0.20.2 and on 0.21.3/0.21.4 — every criterion passed (rsync_paired 16-18 s).
- Lifecycle requeue: reachable classes measured ~0 (RECLAIMABLE 7091/lap dominates); requeue=1 clean.

## Failed/reverted (evidence kept)
- Admission gate at acquire (ag_readopt_window_ms=50): arm 3 wedged 2 nodes (blocking ILOCK holder waited), arm 4 livelocked 1.5-2.2M/lap and starved peers. Knob stays -1. Next = latch at last-holder unlock (ULBP) — see ccloop-c7ee71c6-sess390-readopt-close-two-failures-latch-design.

## Harness lessons
One lap per foreground call; run.sh overhead ~20 s/row; grep --line-buffered; dmesg-only sweeps; never cap prep <300 s.

## Next
1. (C) handoff latch at ULBP + bracket wait_demote as AG wait; A/B at 25 AGs (rsync wall spread, BAST->release p50/p99, zero wedges).
2. Then the RULE-6 queue top (D-FOREIGN-REPLAY-UNGATED-IMAGES etc.). 52 open, 39 critical. CRITERIA NOT MET.
