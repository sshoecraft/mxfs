---
name: sess67-4node-needs-force-block-plus-epoch-adopt
description: sess67: force_block=1 alone passes 1/2 tcp but FAILS 4/tcp dir_reuse (node4_f37 durably lost, round 13). Testing force_block=1 + dir_epoch_adopt=1.
metadata:
  type: project
---

## sess67 — 4-node dir_reuse needs more than force_block

### Build EE5F752F = 621FD271 + force_block default 0→1 (xfs_mxfs_dlm.c:3251).
- **1/tcp = 16/16 PASS** (build EE5F752F, clean).
- **2/tcp = 17/17 PASS** (modarg force_block=1 on 621FD271; logic identical to EE5F752F default).
- **4/tcp dir_reuse_coherency FAILS**: round 13, ALL 4 nodes durably lose exactly ONE entry `node4_f37` (LOOKUP_ENOENT + REREAD_MISS, missing even on its creator test4 after drop_caches). readdir=399 exp=400. P34-TRYLOCK-STALE fired (test1=4,test3=2) — read-path gen-invalidation's XBF_TRYLOCK fails under 4-node contention, serving a stale cached dir block that a subsequent RMW drains to disk, clobbering node4_f37.

### Mechanism (sess65 root, confirmed): dir inode data-fork EXTENT MAP flip-flops across nodes under concurrent create. force_block fixes logical-block0 (rank1 owns it → enough for 2 nodes) but as the dir grows to LEAF format the SAME divergence recurs on higher data blocks → a non-block0 entry (node4_f37) is orphaned at 4-node contention.

### Hypothesis under test (RULE 4): force_block=1 (block0 singular) + dir_epoch_adopt=1 (xfs_mxfs_dlm.c:7093, sess65 PROVED it converges extent map: all 4 nodes' extent[0] agreed daddr=120). epoch_adopt ALONE was said to "drop the converter's own entries"; combined with force_block (so block0 isn't re-converted) it may converge without dropping. Testing `MXFS_EXTRA_MODARGS="dir_epoch_adopt=1" ./run.sh 4 tcp dir_reuse_coherency`.

### Key reload code: mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:6980); modify prelock mxfs_dlm_dir_modify_reload_prelock (2764) — block-adopt branches gated on if_format==LOCAL (shortform) so DON'T fire for grown leaf dirs; only generic MXFS_IF_DIR_RELOAD reload (post_release=false) runs, skipped if mode==EX (line 2927).

[[sess67-force-block-1-fixes-dir-reuse-2tcp-current-build]]
</body>
