---
name: sess37-NEXT-action-plan-dir-evict-keepguard-and-leafrebuild
description: sess37 NEXT-session crisp action plan for dir_reuse 2/tcp: two separable faces (dir-block stale-RMW keep-guard; leaf-hash via dir_leaf_rebuild). Buil…
metadata:
  type: project
---

## sess37 — dir_reuse_coherency 2/tcp: crisp NEXT-session action plan

Reads with [[sess37-drc-real-root-is-stale-block0-leaf-RMW-not-datainit]] and
[[sess37-leaf-rebuild-off-and-AG-freespace-doublealloc-root]]. Build at session end: **3BDA8147**
(CLEAN baseline — all heavy plain-read detectors P31E/P31F/P37 gated behind mxfs.instr, read-hook
bounded-retry reverted; NO functional change vs sess36's 4D56CB92). Timing solved (MHT=300 via
MXFS_EXTRA_MODARGS). Test still FAILS flakily. Marker NOT written.

### The failure has TWO SEPARABLE faces (both flaky; either can fail a run):
**FACE A — DATA loss** (readdir short, node1_f1..fN contiguous block-0 entries gone, both nodes).
**FACE B — LEAF-HASH hole** (readdir=200, lookup_fail=N, last entries in DATA but not LEAF; P21H-LEAFHOLE).

### What is PROVEN / REFUTED this session (don't re-chase):
- P31E/P31F datainit "clobbers" = BENIGN prior-incarnation freed-block reuse (on-disk inode shortform).
- Read-hook bounded retry (xfs_da_btree.c ~3101) = WRONG PATH (gated !owned_ex = non-modify). Reverted.
- Stale in-core BMAP at modify = REFUTED (P37-STALEBMAP-MODIFY fired 0×; reload refreshes bmap).
- Modify-path evict does NOT fail on locks (P36-EVICT-LOCKED=0); its 25×msleep retry works.
- Medium is COHERENT under EX hold (sess69, differs=0) — NOT a storage durability/FUA bug for 2/tcp.

### FACE A primary suspect: dir-block evict KEEP-GUARD keeps an UNDESTAGED stale base.
`mxfs_dir_evict_data_blocks` (xfs_mxfs_dlm.c ~2036) keeps a block when `undurable` = dirty||pinned||
delwri||!DONE||(in_ail && !incarn_aba && mxfs_dir_buf_is_undestaged(dbp)) (~2226). Premise: in-AIL-
undestaged == this-node-ahead. Cross-node that's WRONG if the LSN discriminator mis-judges a
destaged-prev-tenure block as undestaged → keeps STALE block 0 → RMW clobbers node1_f1..N. This MIRRORS
the AG-meta sess117/120 fix (coldread_discard(pag,true) discards in-AIL bnobt/cntbt UNCONDITIONALLY on
the genuine fresh-from-peer path). FIX IDEA: on the genuine fresh-from-peer dir acquire
(mxfs_dlm_dir_modify_refresh / the post_release reload boundary), discard even "undestaged" dir DATA
blocks UNCONDITIONALLY (Invariant 1 drained our work at release → disk is superset). NEXT STEP: add a
DATA-block analog of P21S (log when a DATA block, not just leaf, is KEPT undurable) + a coherent
in-core-vs-disk live-dirent compare to PROVE the kept block-0 is stale. Then apply the fresh-peer
unconditional discard.

### FACE B: leaf rebuild EXISTS but is DISABLED (mxfs_dir_leaf_rebuild default 0).
`mxfs_dir_rebuild_leaf_from_data` (xfs_dir2_leaf.c:615) reconstructs the LEAF1 hash index from the
coherent union of in-core + plain-bio DATA blocks; bails (no alloc) on overflow/LEAFN. Enabling
`dir_leaf_rebuild=1` RAN it (P26-REBUILD-OK 400×, fills holes) BUT tripped an inode-cluster double-alloc
SHUTDOWN (block 0xc00, xfs_inode_buf_verify) — it EXPOSES a latent AG free-space double-alloc, NOT its
own alloc. So FACE B needs: (1) the AG double-alloc fixed first (see
[[sess37-leaf-rebuild-off-and-AG-freespace-doublealloc-root]]), THEN (2) enable leaf rebuild — OR make
the rebuild also run on the LOOKUP/verify path so a holey durable leaf self-heals on read.

### Run recipe: `export MXFS_EXTRA_MODARGS='inode_mht_ms=300'; bash tests/drc_cap2.sh` (instr OFF =
true-speed, race NOT masked). Analyze: grep drc-FAIL/drc-RDMISS/P21H-LEAFHOLE/P21S-EVICTSKIP-LEAF in
tests/_cap/test{1,2}.log (slice pre-run dmesg ring: the stream-start `lines=NNNN` count). Need ≥3
consecutive clean PASS (instr off) before trusting, then full `./run.sh 2 tcp` = 17/17.
