---
name: sess35-FIX-DIRECTION-gen-bump-on-conversion-and-per-handoff
description: sess35 FIX direction (GPT-5.5 confirmed): round-1 loss = block→leaf conversion reuses daddr120 WITHOUT bumping dir_gen → pre-conversion buffer (gen2)…
metadata:
  type: project
---

## sess35 FIX DIRECTION (GPT-5.5 consult #2, on the DECISIVE trace) — round-1 dir_reuse loss.

### CONFIRMED ROOT: a pre-conversion buffer for dir block 0 (daddr 120) survives a cross-node EX handoff. xfs_dir2_block_to_leaf reuses the SAME daddr (block-fmt→data-fmt, in-place b_ops change) WITHOUT advancing the cluster-visible dir generation. So pre-conversion buffers stay bgen==dirgen==2 = "current" to ALL gen-based guards; a later AIL/delwri writeback of that stale image overwrites the post-add data block (drops node7_f1). PROVEN: node7 P11-DATALOG node7_f1→daddr120 @202.764, then writes daddr120 @202.765 WITHOUT it (24 ent); node6 writes daddr120 as xfs_dir3_BLOCK @203.08 (stale pre-conversion ops). All gen=2.

### THE FIX (GPT-5.5, minimal):
1. **xfs_dir2_block_to_leaf() (xfs/libxfs/xfs_dir2_leaf.c:445)**: in the SAME transaction as the block→data magic/ops change, BUMP dp->i_dlm_dir_gen and stamp dbp->b_mxfs_dir_gen = lbp->b_mxfs_dir_gen = new gen. Do NOT xfs_buf_stale the live dbp (it's valid). Same for xfs_dir2_sf_to_block, xfs_dir2_leaf_to_node.
2. **Write-submit gen guard**: reject/stale any dir buffer whose b_mxfs_dir_gen < current i_dlm_dir_gen (old-incarnation). This is RELIABLE (unlike subset_guard/reflush_skip which were blind→wedge/readdir=0) because only genuine pre-conversion buffers carry the old gen; current writes carry the new gen and pass.
3. **Cross-node propagation**: peer must learn the bumped gen on its next EX acquire (LVB/reload) so its cached pre-conversion block0 (old gen) is detected stale + FUA-refetched, and its EX-demotion must drain+invalidate dirty dir buffers so no old-tenure buffer writes after handoff.

### ★ EXISTING LEVER TO CHECK FIRST: `mxfs_dir_gen_per_handoff` (xfs_mxfs_dlm.c:4488, source shows `= 1` but comment says "DEFAULT 0"). Its comment describes THIS EXACT BUG: "fast-path epoch-handoff gen-bump CAPPED by i_dlm_dir_gen <= i_dlm_dir_loaded_gen → bumps only ONCE per reload cycle, so 2nd+ intra-round fast-path handoff does NOT re-invalidate → cached block stays bgen==dirgen==N, aliases peer-superseded image as fresh = readdir=799 clobber. When set, bump i_dlm_dir_gen on EVERY cross-node epoch handoff (uncapped)." 
- BUT the trace showed dgen=2 NOT advancing per handoff despite this being =1. NEXT SESSION: instrument WHY i_dlm_dir_gen isn't advancing per handoff in round-1 (is mxfs_dir_gen_per_handoff actually firing? is the handoff epoch advancing? the dg_shadow epoch was mostly 0 / advances only on owner-change ~7/round — and the CAP `<= loaded_gen` may still throttle it). The fast-path handoff that doesn't bump is the gap. Fix the gen-per-handoff to TRULY bump on every cross-node handoff (incl fast-path/reaffirm), OR add the conversion-site bump (#1) which is handoff-independent.

### KEEPER = 4703FA18 (==2EAA0090 4/5, all exp params off). Repro+trace: drc_repro_loop.sh 15 "dirwr=1" 2 (~1/4 round-1 HIT; P11-DATALOG + P16-DIRBLK-SUBMIT + P35E show the clobber). Saved trace: tests/tcp/drc_cap/SESS35_daddr120_trace.txt.
### REFUTED this session (do not retry as param flips — all blind to the gen-not-bumped-on-conversion root): epoch-never-0, addname_epoch_refresh (readdir=0), subset_guard (wedge), reflush_skip (readdir=0/2), dir_release_stale (re-enters).
See [[sess35-ROOT-round1-format-transition-block-vs-data-divergence]] [[sess35-HEAD-handoff]].
</body>
