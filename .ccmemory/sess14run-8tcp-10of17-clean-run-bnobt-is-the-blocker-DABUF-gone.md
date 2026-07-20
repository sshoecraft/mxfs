---
name: sess14run-8tcp-10of17-clean-run-bnobt-is-the-blocker-DABUF-gone
description: sess14(ccloop) 8/tcp CLEAN run (build AA8C4934) = 10/17 PASS (was ~1/17). ALL coherency tests pass 8/8 (cache_coherency etc). DABUF_MAP_HOLE GONE. Re…
metadata:
  type: project
---

## sess14 (ccloop) — 8/tcp clean run = 10/17 (build AA8C4934), bnobt is the new blocker

After cleaning all 8 nodes (umount+rmmod) and running `./run.sh 8 tcp` fresh:
**PASS 8/8**: precond, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, rsync_paired (10 tests).
**FAIL**: dlm_scaling 7/8, crash_consistency 0/8, dir_reuse_coherency 0/8, fence_during_write 4/8, fault_netpartition 2/8, soak, tcp_dlm_scaling 2/8.

vs the FIRST 8-node run (~1/17, cache_coherency 0/8) — that was CONTAMINATED (cluster not cleaned, stale-build boot + post-4node state). A CLEAN start is essential at 8 nodes. The empty-content cache_coherency failures from the first run did NOT reproduce clean → were contamination/variance, NOT a real 8-node coherency bug.

### Key shift: DABUF_MAP_HOLE shutdowns ELIMINATED at 8 nodes
The sess14 readdir fix (+ async kick) removed ALL DABUF_MAP_HOLE shutdowns at 8-way (was 17-18 each on test7/8). The remaining shutdowns are **bnobt** (AG free-space btree) corruption: 75 on test1, 2 on test7, +1 "Corruption of in-memory" — this is the long-standing bnobt double-free/double-alloc family (sess42-47/81/88/90), amplified by 8-way AG free-space contention (test1=rank1 does the dir_reuse rm-rf + is coordinator → heaviest AG churn). bnobt corruption shuts down crash_consistency (0/8) which cascades to dir_reuse/fence/netpartition/soak.

### 8/tcp remaining blockers (next sessions)
1. **bnobt AG-free-space corruption** (THE blocker — crash_consistency 0/8 + cascade). AG free-space RMW under 8-way contention. fua_always=1 makes AG-meta READS coherent, so this is a WRITE-side/RMW/release-ordering bug. See prior bnobt memories: sess43 (in-AIL AG-meta must not be discarded), sess47 (stale cached inode inactivation), sess42 (advance b_mxfs_ag_gen only when fresh).
2. **8-way throughput**: tcp_dlm_scaling 2/8, dlm_scaling 7/8 — 8× serialized ops over a 60s window. Handoff cost × 8× ops. May need the dir-EX handoff to be much cheaper (settle is required, see [[sess14run-tdscaling-cost-is-settle-loop-required-asynckick-minor-help]]).
3. Fault-test recovery at 8 nodes (likely cascade from the bnobt shutdown; re-test after bnobt fixed).

### CRITERION STATUS: 1/tcp 16/16 ✅, 2/tcp 17/17 ✅, 4/tcp 17/17 ✅(tcp_dlm_scaling marginal), 8/tcp 10/17 ✗. NOT met. Build AA8C4934 deployed.
See [[sess14run-HANDOFF-final-1and2tcp-100pct-4tcp-16of17-8tcp-needs-hole-and-content-work]] [[sess14run-BREAKTHROUGH-LIO-fua-defaults-plus-barrier-perf-fix]].
