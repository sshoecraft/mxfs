---
name: sess11run-FINAL-entry-vanishes-in-addname-to-commit-window-not-split-not-evict
description: sess11(ccloop) FINAL precise root: lost dirent committed (rval=0) vanishes from in-core CACHED data block within ~250us (addname→durable_signal), SAM…
metadata:
  type: project
---

## sess11 (ccloop) FINAL — the durable dir_reuse loss is INSIDE the create transaction (addname→commit), not split/evict/handoff

### Cleanest repro evidence (PRELOGF probe, dirwr=1, lost=node3_f1.md5 creator=test3 round 15, build E5DFBB14)
test3 single thread comm=bash, dir ino=131:
- 141.945344 P-CRNAME add=[node3_f1.md5] cino=2099122 fmt=2.
- 141.945865 P-CRNAME-DONE rval=0 — ADD SUCCEEDED.
- 141.946104 P-DSIG gen=35 flush=1 (durable_signal, ILOCK_EXCL still held — committed but lock kept across commit).
- 141.946113 PRELOGF daddr=120 names=[. .. node1_f1 node1_f2 node3_f1 node3_f2 ...] (DATA FILES incl node3_f1, the sidecar's neighbor — but NOT node3_f1.md5).
- 141.946120 PRELOGF daddr=112 names=[node1_f17 ...].
- NO third block, NO CACHED=0 line. dir = 2 data blocks (112,120) = size 8192 at this create.
- node3_f1.md5 appears in ZERO PRELOGF/P-RELFLUSH/P11-FLUSH-CLEANSKIP clusterwide.

### What this RULES OUT (decisive negatives this session)
1. NOT the 2→3 block SPLIT: the dir grew to 3 blocks (daddr=4186528) at ~142.58, **0.6s AFTER** the create; the entry was already gone at 141.946. Split is a consequence, not cause.
2. NOT cross-node daddr divergence (refutes sess42 for this case): ALL 4 nodes agree the dir data blocks are daddr 112/120/4186528.
3. NOT an uncached-skip: both data blocks were CACHED at durable_signal (no CACHED=0).
4. NOT a concurrent peer-BAST evict (refutes GPT's leading guess): ILOCK_EXCL is held continuously from xfs_trans_alloc through durable_signal (xfs_trans_commit keeps the inode lock; released later), so no other thread can evict the dir buffers in the window.
5. NOT the read-side gen-stale (FIX3) — refuted earlier.

### CONCLUSION: the committed dirent (rval=0) vanishes from its in-core CACHED data block within ~250us, between the addname switch (xfs_dir2.c) and durable_signal entry, SAME thread, ILOCK_EXCL held, no split, no evict. The only thing in that window is xfs_trans_commit (+ note_dir_modified). => the revert is INTERNAL to the create transaction / commit / addname-placement. Candidates: (a) xfs_trans_roll inside a multi-step addname (node-format) commits an intermediate tp and re-reads the data block from a source missing the entry; (b) a dir2 leaf/node addname bestfree/freespace path that logically "adds" (rval=0, count++) but the entry bytes land in a region reused later in the SAME transaction; (c) an mxfs hook in the commit/CIL path reverting the buffer.

### TOOLING LESSON (important): the POSTADD2 probe — calling mxfs_dir_dump_block_names (fresh xfs_buf_incore + xfs_buf_relse) from INSIDE xfs_dir_createname — CORRUPTS the dir (whole-dir readdir=0). The live transaction holds the dir data buffers LOCKED; the probe's relse drops the transaction's buffer lock/hold. So you CANNOT inspect in-transaction buffers with a fresh lock. PRELOGF (in durable_signal, AFTER xfs_trans_commit) is SAFE. To inspect "after addname, before commit", instrument by walking tp's xfs_buf_log_item list (tp->t_items) or add a log line in xfs_dir2_data_log_entry/xfs_dir2_data_make_free, NOT a fresh xfs_buf_incore.

### NEXT (RULE 4): instrument the addname/commit internals SAFELY
1. In xfs_dir2_node_addname / xfs_dir2_leaf_addname (xfs/libxfs/xfs_dir2_node.c, _leaf.c), log the data block (db/daddr) the entry is written to + whether xfs_trans_roll is called between the data-write and return, for the storm dir. 
2. Add a log in xfs_dir2_data_log_entry (the actual entry byte logging) for storm dir — confirms the entry bytes are logged to a specific block, then PRELOGF shows that block lacks them = the revert step is between.
3. Check whether mxfs hooks fire in the commit/CIL path on dir buffers (any mxfs callback in xfs_trans_commit→xfs_log_commit_cil for dir blocks).

### Tree: E5DFBB14 = clean baseline + inert FIX3 + P11/PRELOGF probes (all dirwr/instr-gated, default-inert, SAFE). POSTADD2 REVERTED. Cluster grub log_buf_len=16M. Repro harness (dirwr=1, light, reliable): /tmp/...scratchpad/drc4_d1.sh (~175s, clean single-dirent repro). Criterion NOT met. See [[sess11run-DECISIVE-dirent-absent-at-durable-signal-entry-handoff-during-create]] [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]] [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]].
