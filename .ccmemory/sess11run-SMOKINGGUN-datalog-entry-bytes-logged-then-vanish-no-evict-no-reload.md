---
name: sess11run-SMOKINGGUN-datalog-entry-bytes-logged-then-vanish-no-evict-no-reload
description: sess11(ccloop) SMOKING GUN: P11-DATALOG proves lost dirent's BYTES are logged to a specific data block (daddr), then vanish from that block's in-core…
metadata:
  type: project
---

## sess11 (ccloop) SMOKING GUN — the lost dirent's bytes ARE logged to a data block, then vanish with no evict/reload

### New probe P11-DATALOG (build 96931768, KEEP — SAFE, lightweight): in xfs_dir2_data_log_entry (xfs/libxfs/xfs_dir2_data.c ~1229), logs `ino daddr name comm` for the storm dir (ino<=256, name 'node*'), dirwr/instr-gated. Uses the passed transaction-held bp (NO fresh buffer lock — unlike the REVERTED POSTADD2 which corrupted the dir by relse'ing tp-held buffers).

### DECISIVE TRACE (lost=node4_f16.md5, creator=test4, dirwr=1, clean 70s repro)
test4 single thread comm=bash, ino=131:
- 37.460501 P-CRNAME add=[node4_f16.md5].
- 37.460818 **P11-DATALOG ino=131 daddr=20934152 name=[node4_f16.md5]** — the entry BYTES are logged to data block daddr=20934152.
- 37.460823 P-CRNAME-DONE rval=0.
- 37.461127 P-DSIG gen=36 (durable_signal, ILOCK_EXCL still held).
- 37.461143 PRELOGF daddr=20934152 names=[node4_f15.md node3_f1 node3_f2 ...] — block 20934152 dumped: contains node4_f15.md5 (the PRIOR entry) + node3 entries but **NOT node4_f16.md5**.
- 37.461158 P-RELFLUSH daddr=20934152 — flushed WITHOUT node4_f16.md5.
- node4_f16.md5 in ZERO PRELOGF/RELFLUSH/CLEANSKIP clusterwide; durably ENOENT.

### So in the 325us between data_log (37.460818) and PRELOGF (37.461143), block 20934152's in-core image was reverted from {...,f15,f16} to {...,f15} (pre-f16 state = the on-disk image). A PRECISE one-entry revert of the just-logged entry.

### What it is NOT (all ruled out with traces this session):
- NO P68-EVDECIDE / P-EVICT-DONE / P106-MR-EVICT for daddr=20934152 in the window (evicts on it are all at 38.12+, after). => NOT the modify_refresh/drain evict.
- NO P62-RELOAD in the window. NO cross-node daddr divergence (all nodes agree 112/120/20934152...). NO uncached block. NOT the 2->3 split (happens 0.6s later). ILOCK_EXCL held continuously (xfs_trans_commit keeps the inode lock) => NO concurrent peer-BAST evict possible in the window. Read-side xfs_da_read_buf pre-read invalidation is gated !owned_ex (skipped under EX); P67 postread off.

### CONCLUSION: the revert is INTERNAL to the addname's own block manipulation or xfs_trans_commit — NOT mxfs evict/reload/handoff. Candidates: (a) the dir2 leaf/node addname's data-block compaction/freescan (xfs_dir2_data_freescan / xfs_dir2_data_use_free / xfs_dir2_data_make_free) reuses/overwrites the just-written slot LATER in the same addname; (b) a transaction ROLL (xfs_trans_roll) inside node_addname re-reads/re-formats the block from a source missing f16; (c) the byte offset node4_f16.md5 was written to gets re-allocated to a node3 entry (intra-block bestfree double-use). Note PRELOGF block has node3 entries WHERE node4's md5 run should continue — consistent with slot reuse/overwrite by a peer-or-self entry.

### NEXT (RULE 4): add SAFE tracing (passed bp only, no fresh lock) in the addname data-block path
1. In xfs_dir2_data_use_free / xfs_dir2_data_make_free (xfs_dir2_data.c) log (ino, daddr, offset, len) for storm dir — catch a slot reuse over node4_f16.md5's offset.
2. In xfs_dir2_node_addname / xfs_dir2_leaf_addname, log when xfs_trans_roll is called and re-dump (via the tp-held bp) the data block after each sub-step.
3. Confirm whether the SAME byte offset is logged twice (f16 then a node3 entry) to daddr=20934152 within one create — = intra-block bestfree double-allocation = the real root.

### Tree: 96931768 = clean baseline + inert FIX3 + SAFE probes (P11-FLUSH-UNCACHED/CLEANSKIP, PRELOGF, P11-DATALOG, mxfs_dir_dump_block_names) all dirwr/instr-gated default-inert. Cluster grub log_buf_len=16M. Light reliable repro: /tmp/...scratchpad/drc4_d1.sh (dirwr=1, ~70s). Criterion NOT met. See [[sess11run-FINAL-entry-vanishes-in-addname-to-commit-window-not-split-not-evict]] [[sess36-PROVEN-datainit-zeroes-live-block0-root]] [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]].
