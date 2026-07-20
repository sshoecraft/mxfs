---
name: AAA-ccloopdaf5-sess1-PLAN-full-matrix-revalidation-0.10.66
description: ccloop daf50d34 sess1 plan: re-validate ENTIRE caw matrix on 0.10.66 (C5EF60D5). run68=dir_reuse@32 pass#3 LIVE (142837Z). Then 32-full/16/8/4/2/1.
metadata:
  type: project
tags: [ccloop-daf50d34, caw, multipath, criteria, plan]
---

# ccloop daf50d34 sess1 — full-matrix re-validation plan on 0.10.66

## Context at session start (2026-07-12 14:25Z)
- criteria.json: ALL 17 caw-applicable tests PASS at 1/2/4/8/16/32 — but passes span builds 07-06→07-12 (mixed builds; some 07-07T16:49-17:02 blocks at 2/4/8 recorded implausibly fast — provenance murky). No single build has swept the matrix.
- Build 0.10.66 = srcversion C5EF60D535AF290C91B4112 (bmbt-evict double-unlock root fix). dir_reuse@32/caw: run66 PASS + run67 PASS (20260712T043605Z, 32/32) = 2 consecutive on this build.
- Prior session (e8e920f7) validation ladder before YES: run68 (pass#3), re-verify lower Ns, full-32 sweep. Host healthy. dirwr/dirland=0 defaults are correct (all uses are diagnostic gates now; run66/67 passed with 0).

## Plan (tasks #1-#6, sequential, cluster-exclusive)
1. run68: `MXFS_DEV=/dev/mapper/mpatha timeout 5400 ./run.sh 32 caw dir_reuse_coherency` — LIVE, run_id=20260712T142837Z, log $SP/run68.log, SP=/tmp/claude-1000/-src-mxfs/f26bc7b6-bcc5-421f-b4cf-e45f69aa126d/scratchpad. Launched 14:28Z, expect done ~15:35Z.
2. 32/caw other 16 tests, TEST_TIMEOUT=600 (cache_coherency@32 needs ~480s alone), fresh prep, ship config.
3. 16/caw: 16 tests TEST_TIMEOUT=480 (zsl@16 budget 480s) + dir_reuse alone (auto 2240s).
4. 8/4/2 caw: one full ./run.sh each (17 tests, defaults; dir_reuse auto 140*N).
5. 1/caw full (~6-15 min).
6. All green + probe sweeps clean → YES > /src/mxfs/.ccloop/runs/daf50d34-cc16-4192-9dda-6e2589c78764/criteria-met

## Method invariants
- MXFS_DEV=/dev/mapper/mpatha ALWAYS (multipath is part of the criteria).
- Ship config: NO MXFS_EXTRA_MODARGS (run66/67 convention).
- After EVERY run: `scripts/probe_sweep.sh <N>` (NEW script, this session) must print CLEAN — sweeps P-SEMA-OVERUP/DUALLOCK, P-WRCNT-RESUBMIT, P-BLI-DOUBLEDONE, SYSCALL_HANG, shutdown/BUG/Oops across all N rings. Sweep BEFORE any VM recycle (ring dies on reboot).
- Launch pattern: nohup setsid + background until-loop waiter on the log (foreground sleep is blocked by harness; run_in_background waiter gives completion notification).
- RULE 0: outer timeouts derived (prep ~600s@32 + per-test budgets). A timeout IS a FAIL.
- Known un-fixed risk: SYSCALL_HANG scsi_execute_cmd / mass-unmount blk_execute_rq block-layer family (wedge-root-has-moved-to-scsi-layer-2026-07-11) — harness fast-aborts; if it bites, that IS a criteria failure to diagnose (block layer, not xfs_buf).
- Stale-session hygiene checked at start: no rival run.sh, no rogue claude (only aitrader-project sessions, untouched).
