---
name: sess51-BREAKTHROUGH-dir-ex-revalidate-master-authoritative-fix
description: sess51(ccloop) BREAKTHROUGH candidate (build CBE2E8D9, dir_ex_revalidate=1): master-authoritative slow-path re-acquire on published shared-dir EX mod…
metadata:
  type: project
---

## sess51 (ccloop) — BREAKTHROUGH candidate: master-authoritative dir-EX revalidate

### The fix (build CBE2E8D9, gated param `mxfs_dir_ex_revalidate`, default OFF):
In mxfs_dlm_ilock_begin, the cached-dir-EX fast-path divert (xfs_mxfs_dlm.c ~14050) already forces a real slow-path master re-acquire for UNPUBLISHED dirs (the sess-tcp P106-STALE-EX phantom fix). Extended that divert: when `dir_ex_revalidate=1`, a PUBLISHED peer-reachable (`!i_mxfs_self_created && !i_dlm_unpublished`) directory EX-MODIFY ALSO falls through to the slow-path acquire instead of serving the cached i_dlm_mode==EX. On a non-master node the slow path ALWAYS round-trips the master (mxfs_dlm_lock_internal has NO local short-circuit for non-master nodes, dlm.c:1026), so the master (authoritative) REAFFIRMS if we genuinely hold (cheap reaffirm path dlm.c:2919, no eviction) or SERIALIZES if a peer holds (queue+BAST peer, grant us fresh). This kills the PROVEN phantom: a non-master node modifying a shared dir under a cached EX the master already moved to a peer (the count-preserving divergent RMW root, see [[sess51-PROVEN-loss-is-count-preserving-divergent-RMW-phantom-cached-ex]]). The local held-check (mxfs_dlm_held_mode, :13965) couldn't catch it because the local mirror IS the stale state; only the master's chain is authoritative.

### Result (8/tcp dir_reuse, dir_ex_revalidate=1, clean reboot, DRC_STREAM): rounds 1-15+ CLEAN (zero fail markers), healthy rate (~round15 at ~4min). Baseline (C69E3475) failed by round 2/6/11 with single-dirent losses. (Full 24-round result pending at write time.)

### Why earlier sessions missed it: they chased reader-side staleness (epoch/gen/buffer re-read) — all REFUTED (base always fresh by local metrics). The root is a DLM mutual-exclusion (mastership-visibility) hole on TCP, not a buffer-coherency gap. CAW caught the analogous phantom via the on-disk slot bit (sess106/sess107); TCP had no equivalent until this master round-trip.

### NEXT (verify + harden):
1. Confirm repro9 full 24/24 clean (8/8 nodes PASS).
2. Reliability: tests/sess51_drc_reliability.sh with MXFS_EXTRA_MODARGS=dir_ex_revalidate=1 (need to thread the modarg through the harness) — multiple consecutive full-reboot PASS (was ~1/4 baseline).
3. RULE 0 timing: confirm the per-op master round-trip fits the 8-node budget (480s). repro9 rate looked healthy; measure wall. If slow, optimize (lightweight held-QUERY RPC instead of full LOCK_REQ reaffirm; or throttle with a short cached-validity window — but a window reopens the phantom, so prefer the cheaper query).
4. If solid: make dir_ex_revalidate=1 the DEFAULT, then run full ./run.sh {1,2,4,8} tcp suite — confirm no regression (esp. dlm_fairness/scaling perf, and 1/2/4 still pass).
5. Watch the flaky readdir=0 CASCADE mode (separate from single-dirent loss) — may persist; correlate with D-state mxfs-worker teardown wedge.

### STATE: build CBE2E8D9 deployed (gated, default OFF = baseline-equivalent unless modarg). Marker NOT written until full verification. Tree has the gated fix (not reverted — it's promising).
