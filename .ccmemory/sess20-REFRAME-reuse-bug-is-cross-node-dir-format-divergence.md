---
name: sess20-REFRAME-reuse-bug-is-cross-node-dir-format-divergence
description: sess20 DECISIVE REFRAME: the reuse "leaf-hash loss" is actually CROSS-NODE DIR FORMAT DIVERGENCE — for the same dir ino, test1 sees/writes BLOCK form…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — DECISIVE REFRAME of the dir_reuse_coherency bug. Build E98F295F, dirwr=1, dir_reuse_coherency 24-round (FAIL, drc-FAIL test1=4 test2=74).

## SMOKING GUN — the two nodes DISAGREE on the dir's data-fork FORMAT for the SAME inode (ino 131):
- **test1 P16-DIRBLK-SUBMIT ops: only `xfs_dir3_block` (4×)** → test1 treats the dir as BLOCK format (data+leaf-tail in one block).
- **test2 P16 ops: `xfs_dir3_data` (4×) + `xfs_dir3_leaf1` (6×)** → test2 treats the dir as LEAF format (separate data blocks + a leaf1 hash block).
- **P-LEAFWRITE (sess20 leaf fingerprint detector) fired 0×** even though test2 wrote 6 leaf1 buffers — because the detector plain-reads the on-disk block at the leaf daddr and its magic is NOT a leaf (the durable/peer image is block-format), so it skips. CONFIRMS the on-disk block type ≠ the writer's in-core format.

## REFRAMED ROOT: under rm-rf+recreate REUSE churn, the dir's block↔leaf FORMAT TRANSITION (xfs_dir2_block_to_leaf / leaf_to_block) is NOT coherent across nodes. One node converts the dir (e.g. block→leaf, allocating a leaf block + reformatting block→data) while the peer still has the dir's i_df extent map / format cached as the OLD shape. Each node then reads/writes an INCOMPATIBLE structure at the same daddrs:
- A name added by the leaf-format node is invisible to the block-format node's lookup → durable ENOENT (the "lookup_fail", always the peer/node2's entries).
- A node reading a block whose on-disk magic ≠ its cached format → xfs_da_read_buf verifier fail → xfs_trans_cancel → SHUTDOWN (the corruption variant [[sess20-residual-is-daddr-reuse-corruption-not-leafhash]]).

## THIS IS NOT a leaf-hash hash-entry clobber. All sess19/sess20 leaf-write-clobber work (P-LEAFWRITECLOBBER count + content fingerprint) is a DEAD END for the reuse bug — ruled out [[sess20-reuse-leafhash-ruled-out-hypotheses]]. The bug is dir-FORMAT/extent-map coherency, the historical family (sess18 transition leads, sess53/87/111 extent-map/double-alloc).

## NEXT (RULE 4): instrument the dir FORMAT/geometry coherency:
1. Log, per node, the dir's i_df.if_format + i_disk_size + nextents + the data-fork extent map for ino 131 at each round's modify (is_block vs is_leaf). Confirm the two nodes hold DIFFERENT formats simultaneously.
2. The DLM reload-on-acquire (mxfs_dlm_reload_inode) must rebuild i_df (format + extents) from the peer's committed dinode BEFORE any modify. Check whether the format/extent reload fires on the dir EX re-acquire under reuse, or whether a stale cached i_df (block-format) survives a peer's block→leaf conversion. The i_dlm_dir_gen invalidation covers BLOCK BUFFERS but NOT necessarily the inode's i_df FORMAT/extent map.
3. Likely fix locus: ensure dir inode reload re-reads di_format + data-fork extents on cross-node acquire (the dir analogue of the inode-cluster stale-buffer invalidation), so a peer's block↔leaf conversion is adopted before RMW.

## REPRO (reliable, safe): ./run.sh 2 tcp dir_reuse_coherency (row 13). Builds: E98F295F (full leaf-write trace), readahead-disable kept, P20 removed. Criterion marker CLEARED (work continues). [[sess20-dir-reuse-coherency-reliable-repro-characterization]]
