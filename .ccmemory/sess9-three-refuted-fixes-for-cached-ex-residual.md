---
name: sess9-three-refuted-fixes-for-cached-ex-residual
description: sess9: THREE refuted fixes for the ~1/30 cached-EX-outlives-grant stale-base RMW residual (all regressed below build 427DB5AF's 29/30). Best build =…
metadata:
  type: project
---

## Context: see [[sess9-root-durable-revert-and-publish-only-regression]] for the FIXED roots (build 427DB5AF, ~29/30 dlm_fairness, ~15/16 full suite). The remaining residual is the cached-EX-outlives-grant STALE-BASE RMW (durable resurrection; P9-ICD-FAIL=0, P-DOUBLEGRANT=0).

## THREE FIXES TRIED THIS SESSION — ALL REGRESSED, DO NOT REPEAT
- **A) Force slow-path when i_dlm_stale** (added `i_dlm_stale ||` to the dir-strict fast-path gate ~xfs_mxfs_dlm.c:6530, build 58EB95A8): → STARVATION, dlm_fairness `got=7/8` (node1 didn't finish 50 rounds). i_dlm_stale is set too frequently under churn → every op a DLM round-trip+reload = sess43/sess50 timing wall. Result 29/30 but the failure became slowness, RULE-0 risk.
- **B) Relax P9 clean-gate: drop the IN_AIL skip** (keep pin+ili_fields only, build 223CA589): → WORSE 27/30. P9 then reloads while disk is transiently MID-DESTAGE (older than our just-committed removal) and REVERTS it. The IN_AIL skip is PROTECTIVE against the destage race.
- **C) Race-safe di_lsn gate** (drop IN_AIL skip but only adopt disk if on-disk `di_lsn >= our IN_AIL li_lsn`, build 05431C4F): → WORSE 27/30 (got=3, got=1, got=8 starvation). Theory was di_lsn distinguishes "peer newer" (adopt) from "our mid-destage" (keep); empirically did not improve and added latency. di_lsn semantics / reload cost not as clean as hoped.

## KEEP: build 427DB5AF (best). The deep residual needs a DIFFERENT class of fix:
1. **DLM deferred-BAST resolution** (not a per-op reload): the real defect is a node holding stale cached EX after a deferred BAST. Make the deferred BAST be HONORED (demote+drain) at the next natural boundary (pin released / op complete) so the peer gets a clean reloaded handoff — WITHOUT forcing a reload on every acquire (that starves). Investigate bast_notify deferral (xfs_mxfs_dlm.c ~4540, sets i_dlm_stale on ACQUIRING/pin) and whether deferred BASTs are ever re-driven to a demote; plus sess50 defer_for_waiter / fairness so the churning node yields.
2. Consider RULE-5 Gemini consult ONLY after instrumenting why the deferred BAST never demotes (per CLAUDE.md RULE 5: need a complete instrumented diagnosis first).
Marker NOT written (criterion 16/16 reliable not met).
