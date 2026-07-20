---
name: sess26-iget-fail-is-real-root-write-side-durable-lostupdate
description: sess26 KEY: dir_reuse_coherency 2/tcp REAL failure = iget-fail (dirent→freed prior-incarnation inode), durable on LUN = WRITE-side data-block lost-up…
metadata:
  type: project
---

## sess26 (ccloop 8ddb16a2) — TRUE ROOT of dir_reuse_coherency 2/tcp, proven via P26-IGET-FAIL. Supersedes the "leaf-hash hole" framing in [[sess26-leaf-rebuild-and-b5-bnobt-fix-progress]].

### PROVEN (RULE 4) — the lookup_fail is an IGET failure, not a leaf miss:
Added P26-IGET-FAIL at xfs_lookup's `xfs_iget` (xfs/xfs_inode.c ~799). The cold-read verify does `[ -e $D/$name ]` = stat. Detectors:
- P26-LKERR (xfs_dir2_leaf_lookup error branch) = **0**, P26-LKFMT (xfs_dir_lookup_args fail) = **0** → the DIR LOOKUP SUCCEEDS (leaf+data find every name).
- P26-IGET-FAIL = **200** on BOTH nodes: `dp=131 name="node2_f10" inum=2099081 err=-2(ENOENT)`. The dirent resolves but `xfs_iget(inum)` returns -ENOENT because that inode is FREE on disk. inums are CONSECUTIVE (2099073,74,75…) = node2's files from a PRIOR round's incarnation. So the dir DATA block holds STALE dirents (previous-incarnation inode numbers); names repeat every round (node2_fN) so only the inum reveals the staleness.
- Both nodes cold-read (drop_caches) the SAME stale inums → DURABLE on the LUN.

### WRITE-side, not read-side (refuted read fix):
`echo 3 > drop_caches` DOES drop clean xfs metadata buffers (xfs_buftarg_shrinker runs under drop_slab), so the cold lookup reads FRESH from the LUN — and still gets the freed inum. Tried (build C99F988B): mirror the modify-path `mxfs_dir_force_evict` bypass onto the READER path `mxfs_dlm_dir_consumer_refresh` (xfs/xfs_mxfs_dlm.c — removed its `!new_incarn && gen==evicted_gen` early-return when force_evict on). RESULT: IGET-FAIL still 200 → the LUN block is DURABLY STALE. = WRITE-side durable dir data-block lost-update under daddr REUSE (the dir is rm-rf'd+recreated each round → inode 131 + data daddrs reused; a node RMW's the reused data block from a STALE prior-incarnation cached base and destages it, reverting the peer's/own current-incarnation dirents). This is the sess69 "durable WRITE-side lost-update" family.

### Why the leaf-rebuild "worked" (build 68485F02, lookup_fail 97→0):
It did NOT fix the leaf per se — its side effect of FUA-reading ALL data blocks (xfs_dir3_data_read) on the create path refreshed the in-core data blocks to current inums. But that same caching of peer blocks then went stale → test2 short readdir. So rebuild is a red herring for the root; DEFAULT it OFF (mxfs.dir_leaf_rebuild=0, done).

### KEEP (validated this session):
- **B5 inactivation-skip** (xfs/xfs_inode.c ~2876): skip destructive inactivation when the per-inode EX acquire failed (EDEADLK) + !local_unlink + !EX + !recovery. FIXES the bnobt double-free 0x8 shutdown (P47/P81/P28). Both nodes stay ALIVE now. PROVEN necessary.
- Runtime param `mxfs.dir_leaf_rebuild` (default 0) gating the rebuild + modify_refresh arm.
- Detectors P26-IGET-FAIL, P26-RDDIR (showed test2 nextents=3/full bmap → content stale not bmap), P26-LKERR/LKFMT/DSCAN.

### NEXT (sess27): fix the WRITE-side durable data-block lost-update under reuse.
The acquire-side evict (mxfs_dir_evict_data_blocks, force_evict=1) + b_mxfs_dir_incarn ABA check is SUPPOSED to drop a prior-incarnation cached block before RMW, but a hole remains under reuse. Suspect: the ABA evict SKIPS the block as "undurable" (dirty/pinned/in-AIL = this node's own in-flight prior-incarn work) and RMW's the stale base; OR b_mxfs_dir_incarn isn't stamped so ABA isn't detected. Instrument the create-path dir data-block RMW: at xfs_dir2_data add/the evict, log block daddr + b_mxfs_dir_incarn vs dp i_generation + the inums present, to catch the stale-base RMW that lands a prior incarnation's dirents. Consider: on a NEW dir incarnation (i_generation changed), the reused data block must be treated as a fresh empty block, never RMW'd from the prior-incarnation cached image (force re-init / unconditional ABA evict incl. undurable for a different-incarn block). Consulting GPT (RULE 5) — proven diagnosis + read-fix refuted + architectural.
</body>
