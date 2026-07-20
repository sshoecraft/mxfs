---
name: sess-tcp-ops-are-fast-flaky-is-barrier-desync
description: 2-node TCP: individual FS ops are FAST (create30=.03s, unlink30=.12s, concurrent same-dir create/unlink sub-second, cross-read .015s). cache_coherenc…
metadata:
  type: project
---

## Timing ground truth (build B77AD901, measured)
- single-node: create 30 files = 0.026s, unlink 30 = 0.117s.
- CONCURRENT same-dir both nodes: R1 create30=.07s unlink30=.33s; R2 create30=.034s unlink30=.29s.
- cross-node read: test1 sees test2's 30 files in 0.015s; 1MB md5 cross-read works.
=> NO operation is slow. unlink is NOT the slow path. concurrent same-dir is fine.

## cache_coherency flakiness is NOT a kernel D-state hang
Ran the test while snapshotting D-state stacks every 5s on both nodes: captured ZERO
relevant (non-kworker) D-state stalls during a run that PASSED. The atime-EX deadlock
(fix 5) was the only true D-state hang and it's fixed. The remaining flakiness
(PASS/PASS, HANG, FAIL+PASS, FAIL+FAIL across runs) is barrier DESYNC: one node lags ~1
barrier-phase behind the other (proven: iter-a trace had test1 at uv_preverify while
test2 still at uv_create) and the MQTT coord_barrier (COORD_TIMEOUT) doesn't recover.
Source of the lag is NOT slow individual ops — likely cumulative small skew across ~16
barriers, or an occasional single slow DLM acquire that didn't reproduce as D-state.
Suspect the test harness barrier as much as MXFS. coherency CORRECTNESS is proven
(counts match, all 4 subtests pass when synced).

## USER DIRECTION (2026-06-14, important)
Don't tunnel on cache_coherency (the hardest test). Baseline ALL 16 `showstat 2 tcp`
tests first to see the overall picture — many likely pass now the crash is fixed. Run
the full suite via `./run.sh 2 tcp <list>` (manifest order, starts at precond_readiness).
Exclude `soak` (hours-long duration test). Then attack failures by impact.

## State
5 code fixes KEEP (build B77AD901): see [[sess-tcp-2node-three-root-fixes]],
[[sess-tcp-progress-subtests-123-pass]], [[sess-tcp-cache-coherency-flaky]]. Full suite
baseline run in progress.
</body>
