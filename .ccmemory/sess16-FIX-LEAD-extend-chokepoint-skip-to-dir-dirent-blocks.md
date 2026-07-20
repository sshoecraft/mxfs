---
name: sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks
description: sess16 SHARP FIX LEAD: an EXISTING guard mxfs_buf_xfsaild_skip_bmbt_write (sess61, P61-CHOKEPOINT-SKIP-BMBT, pal/linux/xfs_buf.c:1715) already skips…
metadata:
  type: project
---

## sess16 SHARP FIX LEAD (found at the relay boundary) for 2/tcp crash_consistency, building on the [[sess16-NEXT-xfsaild-reflush-lingering-bli-hypothesis]] (post-release lingering-BLI stale xfsaild re-flush) and the [[sess16-REFUTES-release-drain-gap-blocks-durable-at-release]] proof (release IS durable; the dropper is an async xfsaild write).

## EXISTING MACHINERY (pal/linux/xfs_buf.c, the single bio-submit chokepoint mxfs_buf_write/submit):
- L1715 `if (mxfs_buf_xfsaild_skip_bmbt_write(bp)) { bp->b_flags|=XBF_DONE; xfs_buf_ioend(bp); return; }` — sess61 fix (P61-CHOKEPOINT-SKIP-BMBT): when the dir's per-inode DLM grant was released (EX->NL) since the buffer was delwri-queued, a stale prior-tenure BMBT-LEAF write is SUPPRESSED at submit (emulate clean completion, no bio) because "the release drain (Invariant 1, while EX) already made every legitimate this-node change durable, so this write is a superseded redundant image." EX/PR-held dirs, reg files, single-node fall through to normal submit.
- This is EXACTLY the re-flush vector — but the predicate `mxfs_buf_xfsaild_skip_bmbt_write` is scoped to BMBT-leaf buffers (btree blocks), NOT dir DATA/leaf-DIRENT blocks (bp->b_ops == xfs_dir3_data_buf_ops / xfs_dir3_block_buf_ops / xfs_dir3_leaf1_buf_ops / xfs_dir3_leafn_buf_ops).

## HYPOTHESIS: crash_consistency loses dir DIRENT entries by the same mechanism the sess61 bmbt fix addresses, but for dir DATA/leaf blocks: after node A releases the dir EX (NL), A's xfsaild flushes a stale prior-tenure dir DATA/leaf buffer (still in A's AIL, li_empty=1+in_ail=1) over the peer's newer durable block -> durable dirent loss. The bmbt guard doesn't cover dirent blocks, so they slip through.

## PROPOSED FIX (RULE 4 — INSTRUMENT FIRST, then patch): 
1. PROVE: extend the P56-style / add a detector at the chokepoint — when about to xfsaild-submit a dir DATA/leaf block (b_ops is one of the 4 dir3 ops) AND the dir inode's i_dlm_mode is NL (grant released), log P16-DIRBLK-STALE-SUBMIT with owner ino + daddr + names + whether it's superseded. Reproduce; confirm an NL-released dir-block write drops entries vs the durable LUN (FUA-compare).
2. FIX: extend the chokepoint skip (or write a sibling mxfs_buf_xfsaild_skip_dir_write) to suppress an xfsaild dir DATA/leaf write when the owning dir inode's per-inode grant is NL-released (same rationale: release fence already made our changes durable; this is a superseded image). Get the owner ino from the dir3 block header (xfs_dir3_blk_hdr.owner / xfs_dir3_leaf has owner) -> look up the inode's i_dlm_mode. EX/PR-held / single-node fall through.
CAUTION: must NOT suppress a legitimate write (only NL-released + superseded). The sess61 bmbt analog is proven safe, so the dir-block analog should be too. Validate FULL ./run.sh 2 tcp 16/16 x3 + watch all coherency tests.

## Where to look: mxfs_buf_xfsaild_skip_bmbt_write definition (grep xfs/xfs_buf_item.c + pal/linux/xfs_buf.c), and how it samples i_dlm_mode/grant. The dir3 block headers carry owner ino (mxfs_dir_data_buf_owner_mismatch already extracts it). Cluster on 895603D7 (15/16 + diagnostics). Repro tests/cc_blockdir_probe.sh (ino131, foreground timeout 280, <15 iter). [[sess16-HEAD-status]]
