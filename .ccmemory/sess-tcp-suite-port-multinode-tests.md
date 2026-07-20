---
name: sess-tcp-suite-port-multinode-tests
description: CRITICAL: tests/suite/ only had cache_coherency for multi-node; 12 manifest entries were stubs. User wants them all wired up as working multi-node te…
metadata:
  type: project
---

## THE GAP (user-flagged, 2026-06-14)
`./showstat.sh 2 tcp` lists 16 tests but only `precond_readiness` + `cache_coherency` had
runnable `tests/suite/*.sh` scripts; the other 13 multi-node entries are MANIFEST STUBS
("PEND no script"). The implementations EXIST (months-old) in `tests/cluster/test_*.sh`
(agnostic-ish, old harness) and `tests/criteria/*.sh` (whole-cluster orchestrators, old
ship-gate). User directive: WIRE THEM UP as working 2-node multi-node suite tests NOW,
based on the existing scripts. This is PORTING, not net-new.

## PORTING RECIPE (proven: strong_consistency ported -> PASS 2/2)
New agnostic suite format (template = tests/suite/cache_coherency.sh): a node-side script
that `source tests/suite/lib.sh`, sees only `$MNT` `$RANK`(=R) `$NODES`(=T), runs
`ck "<desc>" cmd...` / `ckeq "<desc>" exp act`, rendezvous via `coord_barrier <tag>` (MQTT,
off-FS, from coord.sh), ends with `coord_done ...; finish`. run.sh launches it on ALL N
nodes (coord!=none) and aggregates PASS iff every node PASS.
Translate old tests/cluster/test_*.sh:
- `NODE_ID`->`$R`, `TOTAL_NODES`->`$T`, `MOUNT_POINT`->`$MNT`
- `barrier_signal X; barrier_wait X N` -> `coord_barrier X`  (one call, both sides)
- `assert_equals exp act "d"` -> `ckeq "d" exp act`;  `assert_file_exists f "d"` -> `ck "d" test -f f`
- `test_fail` -> a failing `ck`;  drop log_timing/test_begin/test_end -> `finish`
- writers=odd rank, readers=even rank, single-node=both (keep that role logic).

## DONE THIS SESSION (build B77AD901, the 5 code fixes from [[sess-tcp-2node-three-root-fixes]] etc.)
- tests/suite/strong_consistency.sh  (from test_sequential_consistency.sh) -> PASS 2/2 verified.
- tests/suite/zero_silent_loss.sh    (from test_concurrent_write.sh: md5 cross-verify + count) -> testing.
- tests/suite/posix_multi.sh         (from test_concurrent_touch.sh: count/uniq + hardlink/rename POSIX) -> testing.
- tests/suite/mmap_coherency.sh      (NEW: python3 mmap write+msync, cross-node mmap read verify) -> testing.
- tests/suite/dlm_fairness.sh        (NEW: each node hammers shared dir ROUNDS times, all must finish = no starvation) -> testing.

## STILL TO PORT (next sessions) — sources in tests/criteria/
- dlm_membership   <- tests/criteria/online_membership.sh (node join/leave; needs membership ops)
- crash_consistency<- tests/criteria/crash_consistency.sh (writer reboot + survivor replay; needs virsh node kill)
- fence_during_write<- tests/criteria/fence_during_write.sh (fence a writing node)
- fault_netpartition<- NONE (write new: block peer TCP via iptables, verify no split-brain corruption)
- scaling_curve    <- tests/criteria/scaling_curve.sh (rsync rounds 1..N; perf, RULE 0 budget)
- dlm_scaling      <- NONE (write new: lock-throughput vs node count)
- rsync_paired     <- tests/criteria/rsync_paired.sh (paired XFS vs mxfs rsync; perf, 2x-native ceiling)
- tcp_dlm_scaling  <- tests/criteria/tcp_dlm_scaling.sh (TCP DLM lock scaling)
NOTE the criteria/ versions are whole-cluster ORCHESTRATORS (they ssh to nodes themselves +
emit RESULT) — for fault/perf tests it may be cleaner to run them coord=none on node1 and let
THEM drive the cluster, OR port the node-side body to agnostic+coord. Decide per test.

## Current showstat 2 tcp standing
precond_readiness PASS, strong_consistency PASS, cache_coherency FAIL (flaky — see
[[sess-tcp-cache-coherency-flaky]] / [[sess-tcp-ops-are-fast-flaky-is-barrier-desync]]).
Criterion = all of showstat 2 tcp PASS. Remaining: fix cache_coherency flakiness + finish porting.
</body>
