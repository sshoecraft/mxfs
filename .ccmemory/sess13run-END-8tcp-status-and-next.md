---
name: sess13run-END-8tcp-status-and-next
description: sess13 END: 4/tcp 8-consec clean (496C1710); 8/tcp: drc PASS w/ 800s budget, remaining = tds 0/8 (likely budget) + ds 7/8. Next: tds budget/probe che…
metadata:
  type: project
---

# sess13 END state — where the matrix stands

## Builds (final = 3D4A350E, on all nodes; 496C1710 = same minus dirwr-gate on P13-PLACE)
All fixes stacked: FIX-C (entry-locks-before-AG-grants in remove+rename),
FIX-D v3 (iget retry ×8: shell_reload → miss_reload(+FIX-E slot patch) →
vis-nudge; + inodegc_flush when shell mid-teardown), FIX-E (slot-level FUA
patch past the P91 logged-buffer guard), probes P13-SFRM (sf removal ledger),
P56 ours=[names], P13-PLACE (now dirwr-gated), P64 present2.

## 4/tcp: 8 CONSECUTIVE clean 17/17 on 496C1710 (longest streak; ~35 total
session iters). Residual singletons this session: zsl ×1 (silent stale
dinode), fence n4_14 sf-dangling leak ×1 (P13-SFRM armed for next).

## 8/tcp (build 3D4A350E, quieted console + journald 400M)
- iter2: 16/17 (only drc timeout). iter3: 15/17 — drc PASS (after budget
  100*N=800s, measured healthy ~530s standalone 8/8 PASS, recorded in
  TIMEOUT_BUDGETS.md + run.sh case-arm), dlm_scaling 7/8 (got=0 face — CHECK
  artifact /tmp/run_dlm_scaling_* whether P13-SLOTPATCH/GCFLUSH fired and
  didn't converge, or new variant), tcp_dlm_scaling 0/8 (SUSPECT its own
  time budget at 8-node pace like drc — check artifact for empty workers +
  'killed leftover' in /tmp/iter8_r3.log; tds has no >4 case-arm in run.sh).
- fence/netpartition/crash all PASS at 8 nodes across iters.
- 8-node ops ~19ms/create-handoff (P131/P138 stage probes hold the
  decomposition) — perf debt, load-bearing coherency cost.

## Gotchas rediscovered
- Foreground Bash cap 600s: use nohup+log+until-grep loops for >10min runs.
- After killing a suite run mid-flight: nodes wedge (umount/rmmod busy) →
  prep hangs forever → ALWAYS virsh destroy+start test1-8 before rerunning.
- run.sh TEST_TIMEOUT env is overridden by the per-test case-arm.
- tar-over-ssh artifact pull resets mtimes (use in-file kernel timestamps).

## NEXT (in order)
1. tcp_dlm_scaling 8/tcp: check iter8_r3 artifact — if empty-workers timeout,
   measure healthy wall standalone (recycle VMs first!), add case-arm budget
   like drc's, re-iterate.
2. dlm_scaling 7/8 artifact: expect P13 stack converging (PASS) or a new
   variant to chase with the existing probe set.
3. Then: 2/tcp ×2-3 and 1/tcp ×2-3 on the SAME build (fast), plus continue
   4/tcp accumulation and 8/tcp to repeated 17/17.
4. Criteria = 1/2/4/8 tcp at 100% — NOT met yet; marker NOT written.
