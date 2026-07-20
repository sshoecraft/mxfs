---
name: sess14run-SESSION-SUMMARY-and-next-priority
description: sess14(ccloop) SESSION SUMMARY: build AA8C4934. 1/2/4 tcp PASS (1=16/16, 2=17/17, 4=17/17). 8/tcp=12/17 at 600s budget (coherency solid). #1 priority…
metadata:
  type: project
---

## sess14 (ccloop 4cb2d0a2) — SESSION SUMMARY & next priority

### Build AA8C4934 (KEEP, deployed) — source changes
- xfs_mxfs_dlm.c defaults: fua_disable=0, fua_always=1, dir_epoch_adopt=1, dir_epoch_convert_gate=1 (LIO cluster needs FUA reads).
- xfs/xfs_dir2_readdir.c: bump i_dlm_dir_gen only AFTER successful reload (fixed readdir DABUF_MAP_HOLE; eliminated at 4 AND 8 nodes).
- tests/suite/coord.sh: coord_barrier `-C $MXFS_NODES` (was -W 2; ~10s/round fake latency removed; speeds all coord tests).
- xfs_mxfs_dlm.c ~5788: async xfs_log_force(mp,0) before the dir-EX-release settle loop (minor handoff trim, safe).
- Diagnostic params relflush_skip/relsettle_skip (default 0) + tcp_dlm_scaling elapsed log (kept).

### Verified results
1/tcp 16/16 ✅ · 2/tcp 17/17 ✅ · 4/tcp 17/17 ✅ (tcp_dlm_scaling marginal ~41-52s/60s but passing). 8/tcp = 12/17 at TEST_TIMEOUT=600 (all coherency + crash_consistency 8/8 + dlm_scaling 8/8). Coherency is SOLID at 8 nodes; bnobt was a 300s-timeout incomplete-recovery artifact (gone at 600s).

### #1 NEXT PRIORITY (the real remaining correctness bug)
**DABUF_MAP_HOLE in CREATE (addname) and LOOKUP paths for LARGE (LEAF-format, fmt=2) dirs under 8-way contention.** dir_reuse 8/tcp PASSES standalone at 600s but in-suite (after crash_consistency's node-kills) test4 took 251 DABUF_MAP_HOLE "Internal error...Corruption" → FS shutdown → iSCSI conn-error-1020 recovery loop (downstream, not causal). My sess14 readdir fix only covers the readdir path. CREATE/LOOKUP also map dir blocks (xfs_dabuf_map) against a stale data-fork EXTENT MAP when the modify/lookup reload (mxfs_dlm_dir_modify_reload_prelock / mxfs_dlm_dir_consumer_refresh) trylock-BAILS under contention → fresh leaf references a block absent from the stale map → hole → shutdown.
FIX APPROACH (RULE 4, careful, NEEDS clean 8-node test cycles): make the modify/lookup extent-map reload RELIABLE under contention — a bounded-retry of mxfs_dlm_reload_inode in the prelock (called pre-xfs_trans_alloc, only IOLOCK held, so a bounded blocking retry is relatively safe), gated DEFAULT-OFF first, validate it (a) doesn't regress 1/2/4 tcp, (b) cuts the 8-node DABUF storm, then default-on. DO NOT use the reverted in-hole EIO guard (self-amplifies → regressed 4/tcp 0/4).

### #2/#3: tcp_dlm_scaling internal 60s window at 8-way (1200 serialized ops); harness TEST_TIMEOUT is fixed 300s but dir_reuse workload is O(N) (scale the per-test budget — RULE-0-correct). fence/netpartition/soak likely cascade from #1.

### INFRA: 8-node runs WEDGE mxfs modules (rmmod-busy) + leave nodes in iSCSI recovery → reboot via `virsh -c qemu:///system destroy/start` between 8-node runs. Budget extra prep time.

Criterion NOT met. Detailed findings: [[sess14run-8tcp-FULL-MAP-12of17-at-600s-remaining-DABUF-createlookup-iscsi-conn-tdscaling]] [[sess14run-8tcp-dir_reuse-is-CORRECT-passes-at-600s-budget-not-coherency]] [[sess14run-BREAKTHROUGH-LIO-fua-defaults-plus-barrier-perf-fix]] [[sess14run-FIX-readdir-dabuf-map-hole-gen-bump-before-reload-bail]] [[sess14run-tdscaling-cost-is-settle-loop-required-asynckick-minor-help]].
