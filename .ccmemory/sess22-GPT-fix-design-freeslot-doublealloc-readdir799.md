---
name: sess22-GPT-fix-design-freeslot-doublealloc-readdir799
description: sess22(ccloop) GPT-5.5 fix design for dir_reuse readdir799 (free-slot double-alloc): (L3) before xfs_dir2_data_use_free verify freshly-read data_best…
metadata:
  type: project
---

## sess22 (ccloop) — GPT-5.5 fix design for the readdir=799 free-slot double-allocation

GPT CONFIRMED my diagnosis (count-preserving content clobber = free-slot double-alloc) and gave a concrete, false-positive-free fix. Three layers; implement L3 first (most targeted), then L1/L2 if residual.

### MECHANISM (refined): node-format xfs_dir2_node_addname picks the target data block from the FREEINDEX `xfs_dir2_free_t.bests[]` summary (NOT by scanning data blocks). bests[i] should == data_block[firstdb+i].bestfree[0].length. If the freeindex/leaf-bests summary is STALE (overlarge) — kept stale at evict because it was in-AIL-undestaged from THIS node's prior EX tenure while the data blocks WERE refreshed — addname selects a data block that no longer has enough contiguous free space. Production XFS only ASSERTs `bestfree[0].length>=need` (debug); in production it proceeds to xfs_dir2_data_use_free with len>actual-free → carves the small free region PLUS the adjacent live peer dirents → count-preserving overwrite. (xfs_dir2_data_use_free DOES call xfs_dir2_data_check_free, but if the DATA block itself is the stale-kept one, its bestfree is internally consistent with its stale content → check passes → overwrites on destage.)

### FIX L3 (targeted, STRUCTURAL — no content/count compare, no ghost trap): in xfs_dir2_node_addname (and xfs_dir2_leaf_addname), AFTER reading the chosen data block + BEFORE xfs_dir2_data_use_free:
```
need = xfs_dir2_data_entsize(mp, args->namelen);
bf = xfs_dir2_data_bestfree_p(mp, data_hdr);
actual = be16_to_cpu(bf[0].length);
advertised = be16_to_cpu(free->bests[findex]);   // leaf: leaf_tail_bests[dbno]
if (actual < need || advertised != actual) {
    // summary stale vs freshly-read data block -> repair from data block
    if (data bestfree looks inconsistent) xfs_dir2_data_freescan(dp, dbp); // rebuild bestfree[]
    actual = be16_to_cpu(bf[0].length);
    free->bests[findex] = cpu_to_be16(actual);
    xfs_dir2_free_log_bests(args, fbp, findex, findex);  // + data_log_header if freescan'd
    if (actual < need) { RESTART the free-space search (re-run find_free); }   // do NOT use_free
}
// invariant: NEVER call xfs_dir2_data_use_free() unless freshly-read data_bestfree[0].length >= need
```
Why no false-positive: it's a pure ALLOCATOR-consistency question (does the free summary match the data block?), NOT "does my write drop a peer name?" — legit removes keep summary==data consistent; ghost-reuse irrelevant (only compares same-incarnation in-core data block to its own summary).

### FIX L1/L2 (root coherence; needed if L3 residual = the data block itself is stale-kept):
- L1 acquire: evict + FUA-re-read ALL dir2 metadata classes — data (XFS_DIR2_DATA_OFFSET) + leaf/node (XFS_DIR2_LEAF_OFFSET) + **freeindex/free (XFS_DIR2_FREE_OFFSET)** — not just low-offset data blocks. Gate on b_mxfs_dir_incarn==i_generation (ghost guard).
- L2 release/demote: the "keep dirty/pinned/in-AIL because it's our uncommitted work" exception is UNSAFE for dir metadata across an EX loss. Invariant-1 already drains; ensure NO dir-fork buffer (data/leaf/node/free) of this inode/generation survives demotion in a state that can later be used or home-written. If a block can't be evicted (dirty/pin/AIL) at the next acquire, that means release didn't fully quiesce it — fix the release, don't keep+RMW the stale block.

### GFS2/OCFS2: coherence via glock/DLM lock state, NOT write-time content compare — on demotion flush/invalidate ALL metadata (incl allocator/index blocks) of the locked domain; next holder revalidates from disk. The DLM lock protects every allocator/index block used to decide future writes, not just the user dirent bytes. → MXFS must treat data+leaf+node+free as ONE coherent dir-mutation domain.

### NEXT SESSION: implement L3 in xfs_dir2_node_addname (find the use_free call site + the freeindex fbp/findex in scope) — it's the minimal fix. Test on 8/tcp dir_reuse. If readdir=799 persists, the data block is stale-kept → add L1 freeindex-class eviction + verify the data block is refreshed. Keeper build = EFBB9861. See [[sess22-readdir799-is-content-divergent-clobber-count-guards-blind]] [[sess22-readdir799-ruled-out-experiments]].
