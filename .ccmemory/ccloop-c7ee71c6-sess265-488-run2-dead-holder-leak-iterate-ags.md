---
name: ccloop-c7ee71c6-sess265-488-run2-dead-holder-leak-iterate-ags
description: sess265: run2 ag=10 strand — test4 dd 8876 DEAD but holders=1 (P12-HOLDERTASK alive=0); suspected leak = xfs_alloc_vextent_iterate_ags error break af…
metadata:
  type: project
---

# sess265 — #23 run-2 stranded ag=10: dead-holder leak

## Evidence (captured live, specimen preserved)
- caw_slotdump: ag=10 slot 59186 EX held by hb bit 10 = test4, waiters 13/28 (test11/test26). Only strand on the platter.
- test4: `P12-AGBAST-RX ag=10 holders=1 cached=0 holder=8876/dd` + `P12-HOLDERTASK ... alive=0`. No shutdown/dirty-cancel. dd 8876 ran the P270 restart protocol (wouldblock ag=5,6,7), pregrant ag=10 @10466.7, readopt (holders 0->1), dead by 10480 (harness pkill). 52 prior readopts released cleanly. P271 counters ZERO on test4 — sess264 drain paths did not run.
- ag_strand_repair requires holders==0, cannot fire on holders=1.

## Hypothesis (open, not yet instrumented)
xfs_alloc.c `xfs_alloc_vextent_iterate_ags` (~4647): error from ag_vextent_near/size AFTER successful prepare_ag (AG DLM held, agbp set, deferred unlock NOT yet registered — that only happens in vextent_finish out_drop_perag gated on `args->agbp && args->pag`) does `xfs_perag_rele; args->pag=NULL; return error` → DLM holder leaks forever. Trigger: fatal signal in a killable wait inside near/size → error unwind → clean-trans cancel (no shutdown).

## Next
Probe P272-AGITER-ERRLEAK at that break; audit all vextent callers for the same shape; RULE 5 on fix (immediate mxfs_ag_dlm_unlock in the break, mirroring the fix_freelist-error path); then 0.11.493 + 3x scaling_curve + rsync_paired. Slot map for this boot is in handoff.md sess265.
