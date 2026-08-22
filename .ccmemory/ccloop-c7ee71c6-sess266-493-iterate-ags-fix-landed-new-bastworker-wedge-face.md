---
name: ccloop-c7ee71c6-sess266-493-iterate-ags-fix-landed-new-bastworker-wedge-face
description: sess266: iterate_ags dead-holder leak FIX landed 0.11.493 (GPT-approved, P272 probe); run1 FAIL = NEW face: holders=0 cached=1 sched=1 page_ms=330s B…
metadata:
  type: project
---

# sess266 — 0.11.493 iterate_ags fix + new BAST-worker-wedge face

## Landed (0.11.493 sv 9CD98254D9947ED88AA35AC, deployed 32/caw via module_swap_deploy)
- `xfs_alloc_vextent_iterate_ags` error break (xfs_alloc.c ~4647): now registers
  `mxfs_ag_dlm_unlock_deferred(args->tp, args->pag)` gated on `args->agbp` BEFORE
  `xfs_perag_rele`/NULL. Closes the sess265 dead-holder leak (allocator error after
  successful prepare_ag left pag_dlm_holders=1 forever). P272-AGITER-ERRLEAK pr_warn
  at the site is the RULE-4 mechanism probe.
- Discriminant safety proven by audit: `xfs_alloc_fix_freelist` sets args->agbp=NULL on
  ALL error paths (out_no_agbp) and only assigns on success; prepare_ag's own error
  paths unlock the DLM themselves and leave agbp NULL. So agbp set at the error break ⇔
  hold owned and unregistered.
- GPT ruling (sess266): deferred unlock correct (immediate would expose pre-commit AG-meta
  since fix_freelist may have dirtied AGF/AGFL); unlock_deferred takes own perag ref
  (xfs_mxfs_dlm.c:40749) + falls back to immediate unlock on alloc failure → lifetime and
  no-silent-failure checks PASS; drain runs at xfs_trans_free (xfs_trans.c:97) on both
  commit and cancel. GPT follow-ups noted: convert agbp proxy to explicit DLM-ownership
  state (hardening); NO dead-task-based force unlock (masking + corruption risk).
- Sibling audit: this_ag/exact_bno/near_bno keep args->pag set on error → finish registers
  deferred unlock, no leak. __xfs_free_extent error paths unlock immediately, no leak.
  iterate_ags was the ONLY leak site of this shape.

## Run-1 result on .493: FAIL with a NEW face (P272 did NOT fire)
scaling_curve 32/caw 0/32 NO_TERMINAL_RECORD @90s. On-disk: ag=1 EX bit2=test3
(waiters test7,test18,test25,test22,test17); ag=3 EX bit21=test25 (waiters test3,test6,
test27,test23). CROSS: test3 holds ag1 waits ag3; test25 holds ag3 waits ag1.
Holder in-memory (both identical): holders=0 cached=1 sched=1 page_ms=330000+ holder=<dead dd>.
=> BAST worker was SCHEDULED with holders=0 and cached=1 (fully releasable) yet never
completed for 330+s. Distinct from: dead-holder face (holders=1, sess265) and orphan face
(cached=0, P5N-AG-ORPHAN-NAK, sess241). The P5N NAKs seen on non-holder nodes (disk_held=0)
are just broadcast-BAST noise.

## Next
Capture wedged bast_work kworker stacks on test3+test25 (/proc/<pid>/stack safe per RULE 2c;
NOT cmdline). Hypothesis to test: bast_work_fn Phase-2 drain for ag=1 blocks on work needing
ag=3 (cross-AG drain ABBA between the two holders). Specimen LIVE — do not re-prep first.
Slot map this boot in handoff.md.
