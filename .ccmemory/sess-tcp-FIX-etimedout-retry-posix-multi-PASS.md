---
name: sess-tcp-FIX-etimedout-retry-posix-multi-PASS
description: FIX WORKS (build F22321): -ETIMEDOUT retry + 6s acquire-wait recovers lost DLM grant msg → posix_multi 4/4 PASS (was hang/62s). Stall 62s→6s. Run ful…
metadata:
  type: project
---

## FIX VERIFIED — posix_multi 2-node TCP now PASSES 4/4 (build F22321508E13160ACFD9A41)
Root was the intermittent LOST DLM grant/release msg on a contended dir-EX handoff
([[sess-tcp-posix-multi-FINAL-root-lost-dlm-grant-msg]]): the waiter sat the full 60s
MXFS_LOCK_WAIT_TIMEOUT_MS then a manual retry recovered. mxfs_dlm_lock did NOT retry on
-ETIMEDOUT.

### The fix (3 small edits, KEEP):
1. include/mxfs/mxfs_dlm.h: new `MXFS_LOCK_ACQUIRE_WAIT_MS 6000` (separate from the 60s
   membership timeout).
2. dlm/dlm.c: both pending_wait() sites in dlm_lock_impl (remote-master ~L785 and
   local-master ~L1093) now wait MXFS_LOCK_ACQUIRE_WAIT_MS instead of 60000.
3. dlm/dlm.c mxfs_dlm_lock(): added `-ETIMEDOUT` to the retry set (re-runs dlm_lock_impl,
   which re-checks compat — now free since the holder released — and re-fires the BAST).
   Bounded by the existing 10-retry loop; last attempt still returns -ETIMEDOUT.

### Evidence (tests/repro_burst_timed.sh, per-create ms):
- Before: test2 create#N = 62000ms (one create per burst stalls the full 60s).
- After: same create = ~6300ms (6s wait + retry grant). EXACTLY one ~6.3s recovery per burst,
  3/3 burst runs. Then posix_multi (real test, COORD_TIMEOUT default): 4/4 PASS (29.4/29.8/
  17.2/17.1s). Was: hang (no RESULT) / count=100 / rename-miss.

### Note / follow-ups
- There is ~1 lost grant msg PER burst (100% of bursts) — high, systematic (likely a specific
  state transition drops the first grant), not random loss. The retry MASKS it in 6s. A proper
  next-level fix = make the grant/release delivery reliable (master-side re-drive watchdog, or
  seq/ack/resend in send_grant + the LOCK_GRANT/LOCK_RELEASE recv path) so even the 6s is gone
  (RULE 0: 6s for an instant op is still a stall, just survivable). Could also lower
  MXFS_LOCK_ACQUIRE_WAIT_MS (e.g. 2000) to shrink recovery further — but verify it stays > a
  healthy handoff and doesn't churn the release-fence drain (cap 30s).
- Other KEEP changes this session (build carries them): bounded ifree drain (ifree_drain_ms=200),
  bast_notify NONE_mode_held idle-release, P-DIRBAST diagnostic.

### NEXT: run full 2/tcp suite (./run.sh 2 tcp) — cache_coherency/mmap_coherency/dlm_fairness
likely improve too (same lost-grant root). Then port the 9 PENDING tests. Criterion = 2-node
dlm=tcp test 100% successful. Build F22321 on test1+test2.
</body>
