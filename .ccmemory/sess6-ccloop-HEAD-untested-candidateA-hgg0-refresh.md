---
name: sess6-ccloop-HEAD-untested-candidateA-hgg0-refresh
description: sess6(run6614) HEAD build 900BB963 UNTESTED: candidate-A fix — arm gg_refresh when grant_gen query hgg==0 (unreliable mirror, N=8 test7 gg_hgg0=87) f…
metadata:
  type: project
---

## sess6 (run 6614) HEAD — build 900BB963 (UNTESTED, relay boundary)

### CHANGE (xfs_mxfs_dlm.c ~14907, candidate-A fix, UNTESTED):
gg_refresh now arms on `(hgg != 0 && hgg != cached_grant_gen)` OR `(hgg == 0 && !self_created)`. Rationale: N=8 P6-DIRPATH counters showed test7 `gg_hgg0=87` — the grant_gen query (mxfs_v5_dlm_inode_grant_gen) returned 0 (stale/absent local grant mirror, the sess5 "mirror lags/zeros" issue) 87×; when hgg==0 the OLD condition (`hgg != 0`) never armed → a handoff could go undetected → stale base RMW → the ~1-3 scattered dirent loss. hgg==0 for a peer-reachable (!self_created) dir = "can't prove continuous hold" → conservatively refresh (drain_evict is loss-safe). Scoped !self_created so solo dirs pay nothing.

### NEXT SESSION — FIRST STEP: TEST THIS.
1. `scripts/drc_reliability.sh 8 8` — is 8-node dir_reuse now reliable? (ENSURE rsyslog masked on all 8 + clean /root/drc_*.dmesg first — see [[sess6-ccloop-8tcp-16of17-diskspace-was-masking]]).
2. Re-confirm NO regression: `./run.sh 4 tcp` (dir_reuse 12/12) + `./run.sh 2 tcp` (17/17) + `./run.sh 1 tcp`.
3. If 8/tcp dir_reuse now 100% → run full `./run.sh 8 tcp` (expect 17/17) → if all of 1/2/4/8 tcp pass → WRITE THE MARKER.
4. If it does NOT help → candidate A refuted; pivot to **candidate B (release-durability)**: the barrier test PROVED a fully-evicted cold base still loses dirents, and fastret_stale=0 + phantom_total=0 (mutual exclusion holds, gen-coherence holds) ⇒ the peer's committed dir block is not DURABLE on the LUN at cold-read. Check mxfs_dlm_dir_durable_signal coverage for the losing create + the EX-release dir-block drain completeness. See [[sess6-ccloop-8node-DECISIVE-not-stalebase-release-durability-gap]] [[sess6-ccloop-8node-NEXT-diagnostic-missed-handoff-vs-durability]].

### MEASUREMENT COUNTERS in this build (harmless, keep for diagnosis): P6-DIRPHANTOM (serve_total/phantom_*) + P6-DIRPATH (fastret_total/fastret_stale/demoter_bypass/slowpath/gg_armed/gg_hgg0), dumped via `echo 1 > /sys/module/mxfs/parameters/dirphantom_dump`.
### KEEP FIXES (proven): dir_gg_refresh=1 + dir_release_flush_leaf=1 (1/2/4 tcp=100%, 8/tcp=16/17). Fallback shippable = 9AA569A0.
See [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]] [[sess6-ccloop-8tcp-16of17-diskspace-was-masking]]</body>
