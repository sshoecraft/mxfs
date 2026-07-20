---
name: sess-tcp-dlmfairness-degrades-node2-wedge-on-churn
description: dlm_fairness (build F22321) PASSes ~2x then WEDGES: iter3 node2=6/50 rounds + t1 stale-readdir; iters4-6 node2=0/50 (hard wedge persists across runs…
metadata:
  type: project
---

## Sharper characterization (build F22321, tests/repro_pm_loop.sh 6 dlm_fairness)
iter1 PASS (13.9s), iter2 PASS (7.9s), iter3 FAIL (74.4s): t1 `df shared dir drained got=1`
AND t2 `df node2 completed all rounds exp=50 got=6`; iter4/5/6 FAIL (~7s each): t2
`df node2 completed all rounds got=0`, t1 PASS.
=> dlm_fairness PASSes ~twice then DEGRADES: node2 goes from 6/50 to 0/50 rounds and STAYS
wedged across subsequent runs (fast-fail ~7s = node2 can't even complete round 1). A full
cluster reset (tests/setup/reset2_tcp.sh) is needed to recover. This is the classic
contamination/degradation pattern (SESS50-STARVE family), NOT merely the transient
stale-readdir I noted in [[sess-tcp-dlmfairness-residual-is-stale-readdir-selfheal]].

## What it means
dlm_fairness = 50 rounds/node of create+rename+rm in ONE shared dir = the heaviest dir-EX
handoff churn in the suite. Under it: (a) rank1 sometimes reads a stale dir block at the
drain-check (got=1), and (b) node2's dir-EX acquire eventually STOPS making progress (0
rounds) — a starvation/wedge of the EX handoff that the 6s lost-grant retry does NOT cure and
may aggravate (50 rounds × multi-second recoveries). The wedge persists = on-disk/in-core DLM
state for the shared dir inode gets stuck after the first failure.

## THE LAST 2/tcp BLOCKER (others all pass: cache_coherency/posix_multi/mmap/strong/zsl/soak)
Next session, fix dlm_fairness:
1. Reproduce after a FRESH reset2_tcp (it passes 1-2x then wedges — so run repro_pm_loop 6+).
2. When node2 hits 0 rounds, freeze-capture node2's create/rename/rm task stack (tests/
   catch_create_stall.sh pattern) + dmesg both nodes — find WHY node2's dir-EX acquire wedges
   (is it -ETIMEDOUT looping past 10 retries -> -EAGAIN -> op fails? is the dir lock stuck
   DEMOTING? is node2 fenced?). The retry fix turned 60s->6s for posix_multi but dlm_fairness's
   sustained churn exposes a deeper EX-handoff starvation/wedge.
3. Likely need: the master-side grant re-drive watchdog (reliable delivery, no 6s recovery)
   AND/OR readdir-time dir-block refresh for the got=1 stale read. Consider lowering
   MXFS_LOCK_ACQUIRE_WAIT_MS (6000->~2000) to cut accumulation, but that won't fix a hard wedge.

## ACTION TAKEN: cluster left degraded by this characterization -> running reset2_tcp to
recover node2 for a clean handoff. Build F22321 stays deployed. Criterion NOT met.
</body>
