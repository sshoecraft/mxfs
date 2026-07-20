---
name: sess15-incarn-fix-implemented-but-0-fire
description: sess15: buffer-incarnation-stamp fix IMPLEMENTED (build 17DCD050) but P15-INCARN fired 0× — same-inode i_generation discriminator did NOT engage; los…
metadata:
  type: project
---

## sess15 result on the [[sess15-FIX-DESIGN-buffer-incarnation-stamp]] fix. Build 17DCD05088602AB7967AD92 (deployed both nodes, dirwr=1).

## IMPLEMENTED (in tree, KEEP — net-neutral, no regression, P15 fires 0× so behaves like B623A0F0=15/16):
1. struct xfs_buf: new `uint32_t b_mxfs_dir_incarn` (xfs/xfs_buf.h:240, after b_mxfs_dir_gen).
2. xfs_da_btree.c xfs_da_read_buf ~3437: stamp `bp->b_mxfs_dir_incarn = VFS_I(dp)->i_generation` unconditionally for DATA-fork dir reads.
3. xfs_da_btree.c read-hook ~3190: `incarn_aba = (b_mxfs_dir_incarn != 0 && != VFS_I(dp)->i_generation)`; added to the invalidate trigger + bypasses the in-AIL-undestaged keep-guard (owner_aba too). P15-ABA-DIRINVAL log.
4. xfs_mxfs_dlm.c mxfs_dir_evict_data_blocks ~2010: same incarn_aba removes the `(in_ail && undestaged)` undurable term (for the owned_ex create-RMW path where the read-hook is gated off). P15-EVICT-INCARN-ABA log.
Safe rule: incarn==0 (never-stamped, e.g. freshly get_buf-init'd CURRENT block) is NOT treated as ABA → a missed stamp site can't discard live work.

## RESULT: cc_blockdir_probe STILL loses (iter 16, node2 entries). **P15-ABA-DIRINVAL=0 AND P15-EVICT-INCARN-ABA=0 on BOTH nodes** → incarn_aba NEVER true. DIR-STALE-SKIP dropped 10/5→0/1 (likely run variance, not the fix). So the same-inode-number ABA i_generation discriminator did NOT engage at the lost-update.

## WHY incarn_aba=0 (next session — INSTRUMENT, RULE 4): the stale buffer's b_mxfs_dir_incarn is NOT (!=0 && != current i_generation). Candidates: (a) the reused dir inode's on-disk di_gen does NOT bump across the rm+recreate reuse (so old incarn == new i_generation — XFS di_gen behavior for dir reuse needs checking), or (b) the reading node's in-core VFS i_generation is STALE (not reloaded to the new incarnation when it reads the stale buffer — iget cache-hit on a reused inode# without gen refresh), or (c) the stale buffer has b_mxfs_dir_incarn==0 (it was last populated via a path that bypasses the xfs_da_read_buf:3437 stamp — e.g. readahead, xfs_dir3_block_read/xfs_dir3_data_readahead, or xfs_trans_get_buf init), or (d) the loss is NOT actually a same-inode-reuse ABA at the dir-DATA-block read at all (the DIR-STALE-SKIP signal was a correlate, not the clobber path). DECISIVE NEXT STEP: add b_mxfs_dir_incarn + VFS i_generation to the DIR-STALE-SKIP log line AND log them at the P-RELFLUSH of the clobbering write; reproduce; see the actual values. If di_gen doesn't bump (a) → need a different incarnation token (e.g. an MXFS per-create epoch stamped in the dinode/dir3 header). If in-core gen stale (b) → force i_generation reload on iget of a reused dir inode. If bypass path (c) → add the stamp to the readahead/get_buf init sites.

## CONFIRMED ROOT still: [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]] (reuse + tight timing required) and [[sess15-HEAD-status]] DIR-STALE-SKIP signature. The fix MECHANISM (discard the prior-incarnation buffer) is right; the DISCRIMINATOR (i_generation) didn't match — find the right token. Also unresolved: xfsaild may flush the lingering prior-incarnation in-AIL BLI onto the reused daddr regardless (needs xfs_buf_stale/binval-style cancel, not just XBF_DONE clear) — verify whether that is the actual clobber vector. Full suite was 15/16 on B623A0F0; re-run on 17DCD050 to confirm no regression before more changes. [[sess15-FIX-DESIGN-buffer-incarnation-stamp]]
