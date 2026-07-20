---
name: sess-tcp-STATE-5of6-reliable-dlmfairness-residual
description: STATE (build F22321): lost-grant retry fixed 5/6 coherency tests reliably; dlm_fairness STILL intermittently FAILs "df shared dir drained got=1" = re…
metadata:
  type: project
---

## Current state after the -ETIMEDOUT lost-grant fix (build F22321508E13160ACFD9A41)
Two full `./run.sh 2 tcp` passes:
- Run 1: 8 PASS / 0 FAIL / 8 PENDING (all coordinated tests + soak green, incl cache_coherency).
- Run 2 (reliability): cache_coherency, strong_consistency, posix_multi, mmap_coherency,
  zero_silent_loss = PASS; **dlm_fairness FAIL (1/2)**.
=> 5/6 coherency tests now RELIABLE. dlm_fairness is the LAST flaky one.

## dlm_fairness residual bug (the new top blocker)
Reason: `test1: df shared dir drained(exp=0 got=1)`. The test (tests/suite/dlm_fairness.sh):
each node does 50 rounds of `create n_r -> mv n_r n_r.done -> rm n_r.done` in ONE shared dir;
after the "df barrier done" barrier, rank1 asserts `ls $D | wc -l == 0`. It saw 1 leftover.
This is NOT the lost-grant stall (that's fixed) — it is a residual DIR-BLOCK COHERENCY issue:
either rank1 served a STALE cached dir block (the long-standing DIR-STALE-SKIP pin=1 family —
a pinned/gen-stale dir data block returned to a readdir showing a dirent a peer already
removed), or a genuinely leaked/lost dirent under the heavy 100-round same-dir churn. Passed
run1, failed run2 => intermittent, low-rate (1/100 churned entries).

## NEXT (to reach 100%)
1. dlm_fairness: reproduce (it's the cheapest repro of the residual dir-coherency bug now).
   Instrument the rank1 drain-check: re-read the dir twice (does got=1 self-heal to 0? => pure
   stale-read; stays 1 => durable leaked dirent). Then fix the readdir-time dir-block coherency
   (the xfs_da_read_buf DIR-STALE-SKIP path — a pinned gen-stale block must be refreshed for a
   readdir, or the releasing node must drain dir-data durable before the dir-EX handoff). See
   [[sess43-dirdata-pin-rootcause]], [[sess-tcp-posix-multi-FINAL-root-lost-dlm-grant-msg]].
   NOTE: lowering MXFS_LOCK_ACQUIRE_WAIT_MS (6000->~2000) also helps dlm_fairness margins (50
   rounds accumulate multiple 6s lost-grant recoveries -> closer to the barrier).
2. PENDING (8 no-script stubs) still need porting for an unambiguous matrix-100%: dlm_membership,
   scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write,
   fault_netpartition, tcp_dlm_scaling (src: tests/cluster/test_tcp_mesh.sh for the last).

## Criterion NOT met yet. Marker NOT written. Build F22321 on test1+test2; clean (last run
left FS mounted, no wedge). All session fixes are KEEP (see
[[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]], [[sess-tcp-MILESTONE-full-suite-8pass-0fail]]).
</body>
