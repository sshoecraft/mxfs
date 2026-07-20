---
name: sess17-reliability-data-and-marker-decision
description: sess17 reliability: crash_consistency flaky (~1 fail/7 full+iso runs); bug confirmed+unfixed (probe reproduces on 492C8EB7). Marker NOT written despi…
metadata:
  type: project
---

## sess17 — RELIABILITY DATA + marker decision for "2 node dlm=tcp 100% successful".

## crash_consistency runs this session (the criterion test = tests/suite/crash_consistency.sh):
- bm5wxz1p5 (FULL suite, build CD4CAA1D): FAIL 1/2.
- 4× isolation (CD4CAA1D): PASS.
- recovery health-check (492C8EB7): PASS.
- b8n3f1ukb (FULL suite, 492C8EB7): PASS 16/16.
- bk04xvzmy run A (FULL suite, 492C8EB7): PASS 16/16 (verified criteria.json 16 PASS 0 FAIL).
=> ~1 failure in 7 criterion-test runs (~14%). On current build 492C8EB7: 0 fail in 3, but small sample.
- cc_blockdir_probe (MORE aggressive than the criterion test — forces daddr reuse via per-iter mkdir+rm-rf): reliably FAILS in ~5-14 iters on BOTH CD4CAA1D and 492C8EB7 => the durable lost-update bug IS PRESENT in the current build; the ship-gate test just doesn't trigger it every run.

## DECISION: marker NOT written. The criterion "100% successful" is NOT honestly met because: (1) the criterion test FAILED once this session (not 100%); (2) the root-caused durable dirent lost-update [[sess17-CONFIRMED-staleflush-clobber-P17]] is UNFIXED — 492C8EB7 = baseline + DORMANT (default-off) merge + detectors, NO functional fix landed; (3) the aggressive probe still reproduces the durable loss on 492C8EB7. The 16/16 showstat is flaky-passing on timing, not a fix. Writing YES = the dishonest escape the wrapper forbids.

## TO ACTUALLY MEET IT: land the block-level dirent union-merge (merge v2). v1 [[sess17-merge-v1-REFUTED-dlm-shutdown]] shut down the FS (per-entry fresh-txn ILOCK_EXCL churned the DLM grant). v2: ONE transaction holding the dir lock once for all re-adds, gen-gated, reusing the create's tenure. After landing, validate: cc_blockdir_probe clean >25 iters AND ./run.sh 2 tcp 16/16 across MANY consecutive runs (>=5) to prove reliability, watching cache_coherency/zero_silent_loss/rename for regressions.

## BUILD STATE: 492C8EB7 deployed both nodes (merge OFF default, SAFE, healthy). Carries P17-CLOBBER-DROP + P16-DIRBLK-SUBMIT detectors + dormant merge code + dir_merge/dirskip params. Cluster healthy (recovered from the v1 shutdown via virsh destroy+start). [[sess17-FIX-PLAN-blocklevel-dirent-merge]] [[sess17-merge-impl-approach-and-txn-blocker]]
