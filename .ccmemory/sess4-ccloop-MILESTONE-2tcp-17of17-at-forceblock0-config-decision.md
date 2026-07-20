---
name: sess4-ccloop-MILESTONE-2tcp-17of17-at-forceblock0-config-decision
description: sess4(ccloop run6614) MILESTONE: FULL 2/tcp = 17/17 PASS at force_block=0 (build 75F2759C). Recovers sess58. CONFIG DECISION: run force_block=0 for t…
metadata:
  type: project
---

## sess4 (run 6614aa96) — 2/tcp GREEN, config decision made

### MEASURED (build 75F2759C, probes-only)
- **FULL `MXFS_EXTRA_MODARGS='dir_force_block=0' ./run.sh 2 tcp` = 17/17 PASS** (all: cache_coherency 2/2, dir_reuse 2/2, fence_during_write 2/2, fault_netpartition 2/2, tcp_dlm_scaling 2/2, soak, crash_consistency…). All 4 VMs must be up (fence_during_write forces 4 nodes internally). Recovers [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]].
- cache_coherency at DEFAULT (force_block=1) FAILS 0/2 at 2 nodes too (both shut down, 34s) — so sess67's force_block=1 default REGRESSED sess58's 2/tcp. The dir3-block owner-mismatch double-alloc ([[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]]) hits at 2 nodes as well.

### CONFIG DECISION (evidence-based)
Run the ENTIRE criterion at **force_block=0**. cache_coherency is in every node-count suite and REQUIRES force_block=0; force_block=1's only benefit (dir_reuse reliability at 4/8) can't justify breaking cache_coherency everywhere. So: force_block=0 is the base. (Consider changing the compiled default 1→0 at xfs/xfs_mxfs_dlm.c:6607 so bare run.sh works — but VERIFY dir_reuse 4/8 first.)

### COLUMN STATUS at force_block=0 (build 75F2759C)
- 1/tcp: not yet run this session (expect PASS; single-node, tooling residuals online_resize/dkms_install per [[sess3-ccloop-FINAL-status-table-all-columns]]).
- **2/tcp: 17/17 ✓ GREEN.**
- 4/tcp: 14/17 (dir_reuse 0/4 + fault_netpartition 3/4 + tcp_dlm_scaling 3/4 — the latter two CASCADE from dir_reuse's shutdown; fix dir_reuse → likely 17/17). dir_reuse flaky at 4 (passed 4/4 once, failed 0/4 twice this session).
- 8/tcp: not run; expect dir_reuse + tds-makespan (historical 16/17).

### REMAINING BLOCKER = dir_reuse_coherency reliability at 4/8 under force_block=0
Faces at force_block=0: `xfs_dir_create_child -117` (parent dir-block torn/owner-mismatch) + `xfs_ifree -117` (inobt double-free, P-DIFREE probes ready). Root = the same cross-node dir-block/inode REUSE coherence divergence. FAST repro for the block-double-alloc face: `./run.sh 2 tcp cache_coherency` at DEFAULT (force_block=1) shuts down deterministically in ~34s with P-BLKRV-STRUCT owner-mismatch — but that's the force_block=1 face; for the force_block=0 dir_reuse face use `scripts/drc_reliability.sh 4 5 dir_force_block=0`.

See [[sess4-ccloop-KEY-bare-defaults-beat-force_block0-dir_reuse-3of3]] [[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]]
