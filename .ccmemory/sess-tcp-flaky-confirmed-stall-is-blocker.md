---
name: sess-tcp-flaky-confirmed-stall-is-blocker
description: CONFIRMED: all 6 multi-node TCP tests are logic-correct; failures are 100% intermittent stall→MQTT-barrier-desync. zero_silent_loss flipped FAIL→PASS…
metadata:
  type: project
---

## CONFIRMED diagnosis (build B77AD901)
Ran the 5 ported tests twice + cache_coherency many times. The multi-node suite now has 6
wired tests (cache_coherency + strong_consistency + zero_silent_loss + posix_multi +
mmap_coherency + dlm_fairness; see [[sess-tcp-suite-port-multinode-tests]]). Results:
- strong_consistency: PASS 2/2 BOTH runs (stable).
- zero_silent_loss: run1 FAIL 1/2, run2 PASS 2/2  <-- FLIPPED = proves flaky, logic correct.
- posix_multi: 1/2 then 0/2; mmap_coherency: 1/2 both; dlm_fairness: 1/2 both.
EVERY failure reason is a coord_barrier TIMEOUT (e.g. "zsl barrier write-done",
"pm barrier create-done", "df barrier done") with the data-check failures being DOWNSTREAM
cascades (peer's files "not yet there" because the barrier desynced). dlm_fairness's actual
50 lock-churn rounds PASS; only its barriers time out. => test LOGIC is correct everywhere.

## The barrier is NOT the bug
coord_barrier (tests/suite/coord.sh) publishes its rank RETAINED *before* polling, so it
tolerates arrival skew up to COORD_TIMEOUT (30-40s). 8/8 distinct barriers pass ~2s each in
isolation. A timeout therefore means a REAL >30s lag: one node intermittently stalls in an
FS op for tens of seconds, the peer's next barrier times out, cascade. Which node stalls is
RANDOM (alternates) => not a bad node, an intermittent code stall.

## THE ONE REMAINING BLOCKER = intermittent >30s FS-op stall on TCP DLM
Same class as the atime-EX deadlock already fixed (was 122s in mxfs_dlm_ilock_begin), but a
DIFFERENT path still does it occasionally. Prime suspects (sleeping DLM acquire = D-state):
- the P-TCP-VERIFY-COORD reader coord: `mxfs_dlm_ilock_begin(ip, PR)` BASTs a peer's
  deferred-publish EX; if the peer is slow to release, PR stalls.
- any remaining ILOCK_EXCL acquire on a hot cross-node path.
- a TCP DLM lock request waiting on a BAST/grant that is slow/lost (dlm/dlm.c retry path).

## NEXT (catch it live, then fix root)
posix_multi is the best repro (fails ~every run, 100 concurrent creates+hardlink+rename).
Run it while sampling `/proc/<pid>/stack` of every non-kworker D-state task every ~3s on both
nodes (catcher running as of this note -> /src/mxfs/.testlogs/pmc_stalls.log). The captured
top mxfs frame names the stuck acquire; fix that path (mirror the atime-EX fix: avoid the
cluster lock, or fix the peer-release latency). Then re-run all 6 — they should go 2/2.
DO NOT widen COORD_TIMEOUT to mask it (RULE 0).

## Also still to PORT (next): dlm_membership, crash_consistency, fence_during_write,
fault_netpartition, scaling_curve, dlm_scaling, rsync_paired, tcp_dlm_scaling (sources +
recipe in [[sess-tcp-suite-port-multinode-tests]]).
</body>
