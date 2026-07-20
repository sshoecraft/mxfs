---
name: sess67-force-block-1-fixes-dir-reuse-2tcp-current-build
description: sess67: dir_force_block=1 (modarg) makes dir_reuse_coherency 2/tcp PASS on current build 621FD271. Regression check vs full suite in progress.
metadata:
  type: project
---

## sess67 (ccloop 4cb2d0a2) — force_block=1 fixes dir_reuse_coherency 2/tcp on current build

Criterion for THIS run: get 1/2/4/8 node tcp dlm test working 100%.
Current build srcversion `621FD271B9A2F505686CC08` (all sess65 module params default OFF).

### Baseline (criteria.json, force_block=0): only failing test across 1/2/4/tcp is `dir_reuse_coherency` (2/tcp=0/2, 4/tcp=0/4). ALL other tests PASS at 1/2/4 nodes. 8/tcp not yet recorded.

### MEASURED (RULE 4): `MXFS_EXTRA_MODARGS="dir_force_block=1" ./run.sh 2 tcp dir_reuse_coherency`
→ **PASS (nodes_pass=2/2)** after clean virsh reboot of all 4 nodes.
This reconfirms sess43's finding (force_block=1 default → dir_reuse PASS) holds on the much newer current build.

### force_block mechanism: forces multinode fresh shortform dir → BLOCK format at mkdir (mxfs_dir_should_force_block, xfs_mxfs_dlm.c:3265). Eliminates cross-node sf→block CONVERSION divergence (two nodes independently converting a fresh shared dir → logical block0 split → dirent loss).

### OPEN QUESTION being measured now: sess44 claimed force_block=1 REGRESSES dlm_fairness/cache_coherency (force_block keeps dir BLOCK in-core while a churning peer converts it to SHORTFORM on disk → P43B overrides P34D → bnobt double-free shutdown). BUT that was a 40-session-older build; the current build has the sess49 P43 soundness gate (P43 fmtrevert-skip gated on dfr_dirty || EX, so a clean PR/NL cacher adopts the peer's durable shortform). Running FULL `./run.sh 2 tcp` with force_block=1 to confirm no regression. If clean → set dir_force_block=1 default + run 1/4/8.

[[sess43-CRITERION-MET-dir-reuse-2tcp-three-clean-passes]]
</body>
