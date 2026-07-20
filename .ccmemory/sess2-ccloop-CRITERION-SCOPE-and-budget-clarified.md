---
name: sess2-ccloop-CRITERION-SCOPE-and-budget-clarified
description: sess2(ccloop) CRITICAL scoping: the 1/2/4/8 tcp criterion = FULL ./run.sh suite (criteria.json). Gaps = ONLY dir_reuse 8/tcp (the blocker) + 16 tests…
metadata:
  type: project
---

## sess2 — criterion scope + RULE-0 budget clarified (changes the whole picture)

### The criterion "1/2/4/8 node tcp dlm test working 100%" = the FULL `./run.sh {1,2,4,8} tcp` suite, tracked in /src/mxfs/criteria.json (run_coord `record`s each test's PASS/FAIL per `N/tcp`).

### EXACT GAPS (computed from criteria.json vs expected test×node matrix): only 17:
- **dir_reuse_coherency 8/tcp** — THE real blocker (my work). (1/tcp N/A: min_nodes=2.)
- **16 tests at 2/tcp** — cache_coherency, crash_consistency, dlm_fairness, dlm_membership, dlm_scaling, fault_netpartition, fence_during_write, mmap_coherency, posix_multi, precond_readiness, rsync_paired, scaling_curve, soak, strong_consistency, tcp_dlm_scaling, zero_silent_loss — these ALL PASS at 4/tcp AND 8/tcp but were simply **NEVER RUN at 2 nodes**. 2-node is the easiest multi-node case → almost certainly pass; just need **`./run.sh 2 tcp`** to record them. CAVEAT: `soak` 2/tcp is a DURATION test (budget 1h+) — check if required / has a short mode.

### RULE-0 CORRECTION (I was wrong earlier): `run_coord` (run.sh:222) runs dir_reuse 8/tcp per-node with a hard `timeout` of **60*N = 480s** (the RULE-0 budget). A node exceeding 480s → no RESULT:PASS → test FAILS. So my **8/8 PASS at inode_mht_ms=1500 ALREADY means dir_reuse 8/tcp completes WITHIN its 480s RULE-0 budget.** mht=1500 is NOT a RULE-0 failure for dir_reuse. (My earlier "535s too slow" included the VM reboot, which is NOT part of the test budget — prep_cluster is separate.)

### So dir_reuse 8/tcp is effectively SOLVED at mht=1500 (8/8 correct + within 480s budget). REMAINING concerns:
1. **Recording**: my drc_reliab_iter→run.sh runs did NOT persist an 8/tcp record in criteria.json (only yesterday's 2/4 tcp shown). Investigate: maybe MXFS_EXTRA_MODARGS path, or a clean (non-mkfs-failing) run is needed. The next session MUST get a clean `./run.sh 8 tcp dir_reuse_coherency` to PASS+RECORD.
2. **mht=1500 global side-effects**: does it regress OTHER 8-node tests (esp. tcp_dlm_scaling — sess20: larger mht pushed its ~60s window)? Either (a) run full `./run.sh 8 tcp` at mht=1500 to verify no regression, or (b) implement the write-side fix so DEFAULT mht=300 makes dir_reuse pass (no global mht change → zero regression risk). (b) is cleaner. My epoch fix (build 5240351B) at default mht = corruption-free but ~2/3 (write-side residual remains).

### NEXT-SESSION PLAN (concrete, high-value):
1. Clean reboot test1-8 → `MXFS_EXTRA_MODARGS='inode_mht_ms=1500' ./run.sh 8 tcp dir_reuse_coherency` → confirm PASS + verify criteria.json records `dir_reuse_coherency 8/tcp PASS`. (If record doesn't persist, debug run.sh `record`/CRIT path.)
2. `./run.sh 2 tcp` (default mht) → records the 16 missing 2-node tests (handle soak: skip or short mode). Likely 16 PASS.
3. Decide mht: verify mht=1500 full-suite-8 no-regress OR land the write-side fix for default-mht dir_reuse. 
4. Re-check criteria.json gaps → if all PASS (modulo soak policy), criterion MET → write marker.

### Build 5240351B (KEEP) = EA485CE6 + leaf/block DATA + LEAF-HASH addname epoch-refresh + P2 probes. inode_mht_ms=1500 modarg gives 8/8 dir_reuse 8/tcp.
See [[sess2-ccloop-BEST-CONFIG-epoch-fixes-plus-mht1500-3of3]] [[sess2-ccloop-FINAL-epoch-fixes-banked-corruption-gone-residual-is-writeside]]
