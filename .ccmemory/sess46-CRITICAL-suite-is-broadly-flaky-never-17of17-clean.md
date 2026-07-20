---
name: sess46-CRITICAL-suite-is-broadly-flaky-never-17of17-clean
description: sess46 CRITICAL: clean full ./run.sh 2 tcp is BROADLY FLAKY — 3 clean reboot+full runs gave 15/17, 16/17, ≤16/17, each failing DIFFERENT tests (dir_r…
metadata:
  type: project
---

## sess46 — THE SUITE IS BROADLY FLAKY (the real obstacle to the criterion)

### 3 clean reboot+full `./run.sh 2 tcp` runs this session (build EF006296, ZERO code edits):
- **repro#1: 15/17** — FAIL crash_consistency(empty .md5 node1_f46-50), dir_reuse(leaf-hash got=15, round 1).
- **repro#2: 16/17** — FAIL dir_reuse ONLY (leaf-hash, round 1). crash_consistency PASSED.
- **repro#3: ≤16/17** — dir_reuse PASSED all 24 rounds(!); FAIL fence_during_write (node1 not fenced/shutdown in window → test1 shut down + UNMOUNTED → contaminates tests 15-17).

### CONCLUSION: NO clean full run hit 17/17. Failures are TIMING/ALLOCATION-DEPENDENT RACES that hit DIFFERENT tests each run:
- **dir-coherency leaf-hash family** (dir_reuse / crash_consistency / cache_coherency): in-AIL stale leaf RMW, write-side clobber CONFIRMED (P-LEAFWRITE). dir_reuse failed round-1 in 2 runs but PASSED all 24 rounds in run 3 → the round-1 failure needs a specific cumulative stale-daddr-reuse state, NOT deterministic. See [[sess46-PROVEN-dir_reuse-leaf-hole-is-async-evictring-lag-stale-leaf-RMW]] [[sess46-dirwr-confirms-writeside-leaf-clobber-and-fix-plan]].
- **fencing family** (fence_during_write): `fdw node1 still writable / no fence/shutdown in window(exp=0 got=2)` — node1's self-fence/shutdown was too SLOW (didn't fire inside the test's window), then shut down LATE. A separate timing issue (fence latency), NOT dir-coherency. May be its own root or contamination from the preceding fault test.

### IMPLICATION FOR THE CRITERION "2 node dlm=tcp test 100% successful":
A single lucky 17/17 run would NOT satisfy it — the suite must pass RELIABLY (the criterion is "100% successful", and 2-3 of 3 clean runs fail). Validation of ANY fix needs MANY runs (5-10+), since a flaky failure may not reproduce in 1-3 runs. This is a MULTI-SESSION effort to close several independent timing races.

### NEXT-SESSION PRIORITIES (ordered):
1. The user's showstat "17/17" is ACCUMULATED criteria.json (single-test re-prep runs each record 1 PASS). NOT a clean run. Always verify with no-arg `./run.sh 2 tcp` after clean virsh reboot of BOTH nodes; trust only the per-run log, not showstat.
2. dir-coherency leaf-hash: the fix is upstream (prevent stale-base leaf RMW) — see fix-vectors map [[sess46-dir_reuse-fix-vectors-and-hazards-map]]. The write-side content-suppression has a RULE-0 perf risk (FUA read per leaf write). Need the FAILING-round P34-LEAF-DRAIN + grant trace to resolve whether node1 RELEASED (leaf should destage) or HELD EX — repro#3 PASSED so gave no failure evidence; re-run until a round-1 failure, capture to SOURCE TREE (not node /tmp — reboot wipes it; lost the sess46 capture that way).
3. fence_during_write: instrument the fence/shutdown LATENCY vs the test's window; may need faster self-fence on the fault path.
4. KEEP sess45 partial-iwrite fix. Build EF006296 is the baseline. force_block=0 (force_block=1 regresses dlm_fairness/cache_coherency).

### INFRA LESSON: dmesg capture via `systemd-run --unit=dmesgcap --collect bash -c 'dmesg --follow > /tmp/dfollow.log'` works but /tmp is wiped on node reboot — COPY evidence to /src/mxfs/tests/_cap/ (NFS = clyde) BEFORE any reboot (RULE 3). dirwr=1 is NOT a clean repro vehicle (perturbs timing → DABUF_MAP_HOLE shutdown on crash_consistency, blows rsync_paired window).</body>
