---
name: sess2-ccloop-ROOT-PROVEN-leaf-block-addname-missing-epoch-refresh
description: sess2(ccloop) ROOT PROVEN (P2-EPOCHPLACE probe, build 7BC9B398): the round-1 dir_reuse stale-base double-alloc = LEAF/BLOCK-format addname has NO epo…
metadata:
  type: project
---

## sess2 — ROOT of the mht=1500 residual round-1 loss: leaf/block addname missing epoch refresh

### PROVEN via P2-EPOCHPLACE probe (build 7BC9B398 = EA485CE6 + cheap always-on in-mem epoch probe at xfs_dir2_data_log_entry placement, BEFORE the sess16 b_epoch stamp):
On a PASS run (corruption-free, cluster stays up), peers showed **stale_base placements**: e.g. `P2-EPOCHPLACE ino=131 name=[node2_f2] master_ep=48 valid_ep=48 b_ep=46 stale_base=1 comm=dd` (test4: ep17/b13; test6: ep26/b24). I.e. a dirent is written into a DATA block whose coherent-read epoch (b_ep) LAGS the master handoff epoch (a peer modified the dir since this block's base loaded) — the free-slot search used a stale base. These are the cross-node intra-block double-alloc producers (sess44). Most get reconciled; ~20% one survives → the round-1 799/800 loss.

### THE GAP (format coverage): grep proved the addname epoch-staleness refresh (`mxfs_dir_addname_epoch_refresh`, b_epoch<valid_epoch → drop XBF_DONE + restart so the standard read FUA-refetches the peer's image) exists ONLY in **xfs_dir2_node.c (4 refs, NODE format)**. **xfs_dir2_leaf.c = 0, xfs_dir2_block.c = 0.** The dir_reuse storm dir is **LEAF format** (proven: leaf block at off=8388608=leafblk; P15-EXTSHAPE). So every leaf-format addname (xfs_dir3_data_read at xfs_dir2_leaf.c:753 and :1243, then bestfree free-slot pick) places on a possibly-stale base with NO refresh. Same for block format. **This is why mht batching only mitigates (fewer handoffs) but never reaches 100%: the leaf-format placement is structurally unprotected.**

### WHY round-1 specifically: a freshly rm-rf'd+recreated dir restarts the master epoch at 0 (dlm.c:2820, "grantee operates in the UNTRACKED REGIME"); the dir grows shortform→block→LEAF under the round-1 concurrent wave, so the hottest contention runs through the unprotected leaf/block addname. Later rounds: dir already leaf-format + epochs established, fewer stale windows. Epoch can't just start at 1 (sess35: caused new_tenure to retire own un-landed work → readdir=0).

### FIX (RULE 4, next): port the xfs_dir2_node.c epoch-refresh (node.c ~2034-2148: if dbp->b_mxfs_dir_epoch < master/valid epoch and the block is CLEAN, `dbp->b_flags &= ~(XBF_DONE|_XBF_FUA_FRESH); xfs_trans_brelse; goto restart;` so the data block is FUA-refetched coherently before the free-slot search) into:
1. xfs_dir2_leaf_addname (xfs_dir2_leaf.c, the data-block read for placement, ~line 730-790 / 1235-1260) — PRIMARY (dir is leaf format).
2. xfs_dir2_block_addname (xfs_dir2_block.c) — for the block-format transition window.
Gate on mxfs_dir_addname_epoch_refresh (already default 1) + multinode + ino<=256-equivalent (published dir). Keep the CLEAN-only guard (never refresh own dirty/in-AIL/pinned — that's our un-landed work). This should make placements coherent at LOW mht → fixes BOTH correctness AND RULE-0 (no need for mht=1500).
3. VALIDATE: build, run at DEFAULT mht=300, capfail ×many (bug ~20% flaky); P2-EPOCHPLACE stale_base count must drop to ~0. Then ./run.sh {1,2,4,8} tcp full suite.

### Probe P2-EPOCHPLACE (build 7BC9B398) is KEEP as the regression detector (always-on, cheap, non-perturbing — stale_base=1 count must reach 0). Located xfs_dir2_data.c just before the sess16 stamp.
See [[sess2-ccloop-mht1500-residual-is-clean-round1-single-dirent-loss-no-corruption]] [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]] [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]]
