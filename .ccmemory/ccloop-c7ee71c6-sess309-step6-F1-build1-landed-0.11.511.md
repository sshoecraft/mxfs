---
name: ccloop-c7ee71c6-sess309-step6-F1-build1-landed-0.11.511
description: sess309: step-6 F1 build-1 LANDED+BUILT 0.11.511 sv EB44E6A843CF082A799AF9D — defer gate, worker, wedge+pin, admission closure; NOT deployed
metadata:
  type: project
---

# sess309 — step-6 F1 deferred-release enforcement, build 1 landed

Implements items 1-10 of the sess308 implementation map (handoff.md) per the
sess307 ruling. Tree 0.11.511, sv EB44E6A843CF082A799AF9D, make clean +
modules + tools all clean. NOT deployed (fleet on 0.11.510).

## Key shapes (xfs/xfs_mxfs_dlm.c ICLUS block)
- `mxfs_release_proof_enforce=1` (0444 load-time), extern in xfs_mxfs_dlm.h.
- `mxfs_iclus_disk_release` now takes `ic` as a PARAMETER (was internal
  iclus_get) — the old lookup raced purge_all's unhash and would have
  silently disabled the defer gate mid-teardown. All 5 callers have ic.
- Defer gate after tripwire eval on {oblig_cas, proof_failed, tripwire};
  publish-fail routes through same helper (badness 8). cas_attempted=1
  moved after the gate so a deferred cert reads cas_attempted=0.
- `mxfs_iclus_defer_arm`: episode fields under ic->lock; progress = badness
  DECREASE; bounds 60s no-progress / 300s total → wedge; worker backoff
  min(25ms<<min(tries,5),1s)+jitter queued UNDER ic->lock (pairs with
  purge_all's no_retry-then-cancel_sync — closes the schedule-after-cancel
  use-after-free race).
- SESS309 REFINEMENT beyond the sess308 map: a FAILED CAS under enforcement
  must NOT reopen admission (old tail set ACTIVE unconditionally). It stays
  in the episode via defer_arm(badness 16). Reason: the worker's
  granted-only covered_active sweep is only sound while DEMOTING blocks new
  grant stamps for the WHOLE episode; an ACTIVE window would let a
  fast-admit open (mode not yet stamped → invisible to granted-only sweep)
  and the next worker release would strip live coverage.
- Wedge: one-shot, pins grant via mxfs_v5_dlm_iclus_pin →
  mxfs_dlm_caw_pin_resource (ctx->pinned_res[4] under held.lock);
  release_all refuses pinned slots (n_lost++ → clean departure refused →
  peers fence/recover). P-ICLUS-WEDGE, P-WEDGE-PIN, P-WEDGE-PIN-RELEASEALL,
  P-ICLUS-TEARDOWN-UNPROVEN are the new probes. Shutdown skipped when
  no_retry (teardown).
- Admission: admission_open() = !enforce || state ∉ {DEMOTING, WEDGED};
  fast path, busy-wait park (wakes on open||WEDGED; WEDGED → -EIO),
  try_admit, open_admit. granted_mode untouched (ioend nested-EX).
- release_done_locked() centralizes success bookkeeping incl.
  release_epoch++ (ABA guard) and episode reset — CRITICAL: without the
  reset at every success site, a stale defer_started_j would instantly
  wedge the next episode on the 300s total bound.
- New counter deferred_proof_failed (proof_failed && !cas_attempted).

## Not in build 1 (deliberate — "build 2")
relbar 14948 proof-failed flip to the defer/strand channel + selfclear
suppression per release_epoch (sess308 map item 11). READY consts still 0
until fault-inject verification.

## Next
Deploy 32/caw, FULL board knob=1, knob=0 regression board, then
relgate_fault stages 7/9/10 fault-inject; wedge-path test needs a way to
hold a proof failure long enough (open design question).
