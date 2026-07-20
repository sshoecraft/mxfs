---
name: sess14run-8tcp-FULL-MAP-12of17-at-600s-remaining-DABUF-createlookup-iscsi-conn-tdscaling
description: sess14(ccloop) 8/tcp FULL MAP at TEST_TIMEOUT=600: 12/17 PASS (all coherency + crash_consistency 8/8 + dlm_scaling 8/8). Remaining: dir_reuse in-suit…
metadata:
  type: project
---

## sess14 (ccloop) — complete 8/tcp map with scaled budget

`TEST_TIMEOUT=600 ./run.sh 8 tcp` (build AA8C4934):
**12 PASS 8/8**: precond, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, **dlm_scaling (was 7/8)**, rsync_paired, **crash_consistency (was 0/8 — bnobt was a 300s-timeout-induced incomplete-recovery artifact; with 600s it recovers cleanly, no bnobt)**.
**5 FAIL**: dir_reuse 0/8, fence_during_write 2/8, fault_netpartition 3/8, soak, tcp_dlm_scaling 4/8.

### Remaining 8-node failures = 3 narrow causes (NOT broad coherency — coherency is SOLID)
1. **DABUF_MAP_HOLE in create/lookup paths** (the real correctness bug): dir_reuse in-suite, test4 recorded **251 "Internal error ...DABUF...Corruption"** events + 3 failrounds. dir_reuse PASSES standalone at 600s, but in-suite after crash_consistency's node-kills the contention/state triggers DABUF holes that my readdir-only fix (sess14, xfs_dir2_readdir.c) does NOT cover — CREATE (addname) and LOOKUP also map dir blocks against a stale extent map when the modify/lookup reload trylock-bails under 8-way contention. FIX: apply the readdir principle (no fresh-leaf/stale-map inconsistency) to mxfs_dlm_dir_modify_refresh / consumer_refresh, OR make those reloads reliable (bounded-retry instead of trylock-bail). Do NOT use the reverted in-hole EIO guard (self-amplifies).
2. **iSCSI connection instability at 8 nodes**: test4 dmesg floods `connection1:0: detected conn error (1020)` (ISCSI_ERR_CONN_FAILED) — the initiator↔LIO-target session drops under 8-way load. Could be CAUSAL (storage can't sustain 8 initiators under heavy load → I/O errors → DABUF/corruption) or consequential (FS shutdown drops the conn). NEXT must determine which — if causal, it's an infra/target limit, not an MXFS bug. Check LIO target (clyde) dmesg + load during 8-node runs.
3. **tcp_dlm_scaling 60s window** (4/8): the test's internal WINDOW=60s assertion; 8×150=1200 serialized dir-EX ops vs 60s. DLM throughput scaling. Hard. (fence/netpartition/soak likely cascade from #1/#2.)

### Harness budget (RULE-0-correct): dir_reuse workload is O(N) (EXP=2*T*NFILES); the fixed TEST_TIMEOUT=300 is too short at 8 nodes. dir_reuse passes 8/8 STANDALONE at 600s. A node-count-scaled per-test budget is legitimate (matches workload), but does NOT fix the in-suite DABUF cascade (#1) — that's a real bug.

### Criterion: 1/tcp ✅ 2/tcp ✅ 4/tcp ✅ 8/tcp ✗ (12/17 at 600s). NOT met. Priority next: DABUF holes in create/lookup (#1) + iSCSI conn stability (#2).
See [[sess14run-8tcp-dir_reuse-is-CORRECT-passes-at-600s-budget-not-coherency]] [[sess14run-FIX-readdir-dabuf-map-hole-gen-bump-before-reload-bail]].
