---
name: sess48-phantom-ex-waiter-bit-leak-rootfix
description: sess48 PROVEN ROOT + FIX (build C63A349): posix_semantics_multi16 wedge = leaked CAW EX-waiter bit. Robust caw_drop_own_waiter on give-up paths. NOT…
metadata:
  type: project
---

# sess48 (ccloop 14d31183) — posix_semantics_multi16 ROOT: phantom EX-waiter bit leak

Build `C63A349955BC8AC3721F0E5` (dlm/dlm_caw.c). **Fix landed, NOT yet verified** (infra gap ate the verify run — see below).

## State at session start
Only `posix_semantics_multi16` FAILs (18/19 PASS). On build D9D22CF3 the **dir lost-update is effectively fixed**: cold `--phase cluster` PASSED test_concurrent_mkdir/touch/write (DIR-STALE-SKIP only 0-10/node). The phase instead **WEDGED on the 4th test, test_cross_visibility** → >600s → FAIL.

## PROVEN root (RULE 4 step 2b) — leaked CAW EX-waiter bit
Decisive field evidence on the wedged cluster:
- All ~9 blocked D-state threads across all 16 nodes were **SHARED readers** (`find`/`ls` in xfs_readdir→`mxfs_dlm_ilock_begin`). Scanned every node's `/proc/*/task/*/stack`: **ZERO threads anywhere requesting EX**, no `touch`/`mkdir` procs.
- Yet the slot for **ino=23069101 (the `.mxfs_barriers/<name>` directory)** froze at `waiter_mode=5(EX) waiters=2 h_ex=0 h_pr=0xfe84 gen=3299` (constant) → SESS50-STARVE 500-728×/node + hung_task.
- ⇒ The 2 EX "waiters" are **orphaned bits** with no live waiter. `defer_for_waiter` (dlm_caw.c ~1805: fresh PR/CR/CW acquire defers while `waiter_mode==EX` and other waiters set) then defers **every reader's fresh SHARED acquire forever** → total wedge.

**Why it leaks:** barrier dir is hammered by 16 nodes: `touch signal-file` = create = **PR→EX upgrade** (registers EX waiter bit), `find` wait = PR. A waiter that gives up must clear its `waiters` bit. `caw_wait_for_grant`'s timeout cleanup was a **bounded 10-iteration CAS loop** (old lines ~1084-1100); under the 16-node CAS storm on the hot slot all 10 attempts lose the compare-and-write race → bit left set permanently; once contention ends, gen freezes with the orphan bit and nothing ever re-clears it. The two exhaustion paths (`mxfs_dlm_caw_lock` "lock exhausted", `caw_convert` "convert exhausted") cleared **nothing**. (`msleep` is uninterruptible, so even a SIGKILLed waiter completes cleanup on syscall return — so a robust cleanup also covers the kill case.)

## THE FIX (build C63A349)
New helper `caw_drop_own_waiter(ctx, slot_idx)` in dlm/dlm_caw.c (just before `caw_wait_for_grant`): re-read slot + CAS-clear OUR `node_bit` from `waiters` + recompute_waiter_mode, **retry with backoff until a fresh read confirms our bit clear** (or slot gone), bounded 1000 attempts (backoff cap 8ms). Wired into 3 give-up sites: (1) replaces the 10-retry loop in `caw_wait_for_grant` timeout; (2) before `-ETIMEDOUT` at `mxfs_dlm_caw_lock` exhaustion; (3) before `-ETIMEDOUT` at `caw_convert` exhaustion.

## NEXT (verify) — cluster is STAGED
All 16 VMs were **restarted** (destroy+start) to clear the kernel wedge (D-state finds unkillable), build C63A349 deployed, `tests/reset4.sh 16` mounted fresh FS, dirwr=1, and `/mnt/mxfs-src` **bind mount restored on all 16** (mount --bind /src/mxfs /mnt/mxfs-src — this is REQUIRED for run_tests.sh test scripts and reset4.sh does NOT set it up; without it every test errors rc=127, as happened this session's first verify attempt → false all-FAIL but NO wedge, ran in 3min).
- **Run now:** `MXFS_NODE_OFFSET=16 timeout 560 tests/run_tests.sh --nodes 16 --phase cluster` — expect it to get PAST test_cross_visibility and complete all 14. Watch SESS50-STARVE count (should drop) and confirm no reader wedge.
- Then full criterion: `tests/criteria/posix_semantics.sh --nodes 16` must PASS (single run, <600s). Then `verify_ship.sh` end-to-end for the marker.

Related: [[sess50_lessons]] (defer_for_waiter origin), [[sess123-caw-ex-starvation-gemini-fairness-design]], [[sess43-dirdata-pin-rootcause]] (prior dir-lost-update root, now mostly fixed).
