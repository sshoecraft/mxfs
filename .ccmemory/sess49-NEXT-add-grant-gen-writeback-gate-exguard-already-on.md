---
name: sess49-NEXT-add-grant-gen-writeback-gate-exguard-already-on
description: sess49(ccloop) NEXT STEP: mxfs_dir_ex_write_guard=1 (not-EX writeback skip) ALREADY ON yet clobber persists → clobbers are mode==EX. Implement GPT's…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — the precise next implementation step

### STATE AT RELAY:
- FIXED + BAKED: dir_epoch_adopt=0 (build 3B0EB406) eliminates the 8-node FS-SHUTDOWN (AG double-free from epoch-adopt stale-disk fork-shrink). VERIFIED no shutdowns.
- 8-node dir_reuse residual: FLAKY ~1 PASS/4 FAIL (run49c PASS; run49d, sweep r1, r2 FAIL), NO shutdown. The 130-session write-side dir-block lost-update (FACE1 xfsaild stale block-0 flush + FACE2 reader stale block). 4-node PASSES.
- GPT-5.5 design obtained: DLM-grant-epoch authority. See [[sess49-GPT-design-dlm-epoch-authority-for-dir-buffer-coherency]].

### KEY DISCOVERY (this is the actionable next step):
`mxfs_dir_ex_write_guard = 1` is ALREADY DEFAULT ON (xfs_mxfs_dlm.c:19662) — it skips a dir-metadata writeback when the node does NOT hold EX (dsi.mode != EX). GPT's gate part (a) "writeback requires EX" is therefore ALREADY enforced. Yet the FACE-1 clobber persists → **the clobbers happen while the node holds a (cached/stale) EX grant (mode==EX)**. So ex_guard is insufficient; the MISSING piece is GPT's gate part (b): the per-buffer GRANT EPOCH check.

### IMPLEMENT (GPT FACE-1 fix, RULE 4 — test each):
1. **Birth-stamp** b_mxfs_grant_gen at block init under EX: in xfs_dir3_data_init (xfs/libxfs/xfs_dir2_data.c ~887, where it already stamps b_mxfs_dir_epoch) add `bp->b_mxfs_grant_gen = dp->i_dlm_cached_grant_gen;` (and at leaf/free init). So a fresh current-grant block passes the gate. (Read-completion already stamps it: xfs_da_btree.c:3871, fresh-read only.)
2. **Writeback gate** in mxfs_buf_xfsaild_skip_dir_write (xfs_mxfs_dlm.c ~22226) OR the submit site (pal/linux/xfs_buf.c ~3062): NEW arm, own param (mxfs_dir_grant_write_guard, DEFAULT 1) — skip the dir-meta write when `dsi.in_core && bp->b_mxfs_grant_gen != 0 && bp->b_mxfs_grant_gen != ip->i_dlm_cached_grant_gen` (reliable epoch; NOT the lossy dsi.dir_gen the sess41 dc_stale arm uses). Need to expose i_dlm_cached_grant_gen + b_mxfs_grant_gen via dsi (add fields to mxfs_dir_skip_info) or compute inline in xfs_buf.c. Apply via the existing emulate-clean-ioend path (line 3062-3068). RATELIMITED marker P49-GRANTWB-SKIP.
   - WHY this defeats the ghost (where content/dir_gen failed): a fresh block is birth-stamped CURRENT grant → allowed; a dead-incarnation ghost / stale prior-grant block has grant_gen != current → denied. A current-tenure modify re-read the block under the current grant (stamped current) → allowed.
3. TEST: tests/drc_dirtyskip.sh "" 24 8 (build it, no modargs). Expect FACE-1 (lookup_fail>0 node1_f1..) gone. Then tests/drc_reliability.sh "" 24 5 8 for reliability. Then FACE-2 read gate (reread on b_mxfs_grant_gen mismatch in readdir) if readdir-short (lookup_fail=0) persists.

### WATCH: a writeback-denied DIRTY buffer must retire cleanly (emulate-clean-ioend retires BLI, no AIL wedge — sess37 confirms xfs_buf_ioend retires BLI). Verify no umount/AIL wedge. If a denied buffer carried UN-durable current work it'd be lost — but Inv-1 release-drain is PROVEN durable (sess41), and birth+read stamping means current work has the current grant_gen (never denied).

### Tools: tests/drc_dirtyskip.sh, tests/drc_reliability.sh, tests/drc_capture_clobber.sh (greps P62/P31E/P13/P40/P49), tests/suite_tcp_clean.sh. Criterion = FULL ./run.sh {1,2,4,8} tcp 100% ([[sess49-criterion-scope-is-full-suite-and-verification-plan]]).
</body>
</invoke>
