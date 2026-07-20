---
name: sess4-ccloop-KEY-bare-defaults-beat-force_block0-dir_reuse-3of3
description: sess4(ccloop run6614) KEY CORRECTION: dir_reuse 4/tcp is RELIABLE at BARE DEFAULTS (no modargs: force_block=1 + 4 dir levers=1) = 3/3 PASS. sess3's d…
metadata:
  type: project
---

## sess4 (ccloop run 6614aa96) — RUN AT BARE DEFAULTS, drop the force_block=0 override

### FINDING (RULE-4, measured)
- Build 3A16A85A (= sess3 D567EC9A + P-DIFREE probes, pure logging).
- `scripts/drc_reliability.sh 4 3` (bare defaults, NO MXFS_EXTRA_MODARGS) → **dir_reuse_coherency 4/tcp = 3/3 PASS**.
- Earlier this session with `MXFS_EXTRA_MODARGS='dir_force_block=0'`: dir_reuse 4/tcp FAILED 0/4 (test2 `xfs_dir_create_child err=-117` → dirty `xfs_trans_cancel` shutdown; and in full-suite test4 `xfs_ifree returned error -117` inobt double-free shutdown).
- **CONCLUSION: sess3's `dir_force_block=0` override was HURTING.** The tree's DEFAULTS are the validated config: `mxfs_dir_force_block=1` (sess67), `dir_release_invalidate=1 dir_relinval_clean=1 dir_gen_per_handoff=1 dir_modify_extent_adopt=1` (sess30 keeper). Current source has ALL of these =1 by default (xfs_mxfs_dlm.c:4214,4222,5325,5345,6607).

### ACTION FOR THIS/NEXT SESSION
- Run the criterion with **bare `./run.sh N tcp`** (no modargs). Do NOT pass dir_force_block=0.
- Residual non-fatal noise at defaults: `DLM inode reload imap_to_bp failed rc=-5` (non-fatal reload miss, test still PASSes).
- Next: full 4/tcp + 8/tcp suites at bare defaults; sess30 methodology — dir_reuse is FLAKY, need ≥3 clean runs before claiming.
- Probes added this session (harmless): P-DIFREE-DBL (xfs_ialloc.c difree_inobt, detects inobt double-free), P-DIFREE-CORRUPT (site tags at difree EFSCORRUPTED exits).

See [[sess30-WIN-4tcp-17of17-soak-fixed-by-P30-ops-recover]] [[sess3-ccloop-FINAL-status-table-all-columns]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]
