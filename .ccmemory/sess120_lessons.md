---
name: sess120_lessons
description: sess120 (ccloop s12) — cache_coherency 1/4→3/4. FIXED AG-meta corruption via LSN discriminator mxfs_buf_is_undestaged (build 82BB2A09 KEEP). Remainin…
metadata:
  type: project
---

## sess120 (ccloop 4eef1f39 s12) — build 82BB2A09 (KEEP, deployed all 4 nodes)

### MAJOR WIN: cache_coherency 1/4 → 3/4. FIXED AG free-space corruption.
cross_visibility, rename_visibility, cross_write_read ALL PASS. Only test_unlink_visibility fails.
Zero corruption/shutdown. (Was passed=1 failed=3 at session start.) Marker NOT written.

### ROOT FIXED — P110(keep) vs P117(discard) CONTRADICTION on same in-AIL bnobt/cntbt buffer
Proven (RULE 4): EEXIST-loser self-corrupts its OWN affine AG. P117-INAIL-STALE-ARTIFACT
(mxfs_ag_meta_invalidate_stale) staled a buffer P110-BIO-OVER-LOGGED kept → half-state → cntbt CRC
err74 + AGF verify fail + shutdown. Both fired SAME daddr same instant. In-core AHEAD of disk
(disk pristine len=260906 vs in-core len=7) = case B (keep) but P117 mis-classed as drained
artifact. AG affinity HOLDS (each node own AG) so it was SINGLE-NODE self-clobber, not cross-node.

### THE FIX (Gemini RULE-5, VERIFIED vs kernel src xfs_btree.c:454 xfs_btree_agblock_calc_crc)
New `mxfs_buf_is_undestaged(bp)` (xfs/xfs_mxfs_dlm.c ~4944; proto xfs_mxfs_dlm.h). calc_crc stamps
bb_u.s.bb_lsn = bli_item.li_lsn at WRITE-SUBMIT only; li_lsn advances earlier at CIL→AIL. So:
pinned→true; in_ail && XFS_LSN_CMP(li_lsn, payload_lsn)>0 → un-destaged(true); else false.
payload_lsn from b_addr by magic (AGF→agf_lsn / AGI→agi_lsn / AGFL→agfl_lsn / else btree bb_u.s.bb_lsn).
No blocking IO. Gated sess117 P117 discard branch with `&& !mxfs_buf_is_undestaged(cbp)`. VERIFIED:
repro_double_alloc.sh 25 ALL CLEAN (was iter-2 fail); P117-STALE=0 P110=0 (contradiction gone);
cache_coherency cross/rename/cwr PASS.

### REMAINING: test_unlink_visibility = TIMING-SENSITIVE block-dir-data READ staleness (NOT lost-update)
4 nodes each create 30 files in ONE shared dir (120 entries = BLOCK fmt). Criterion: nodes 1/3/4
fail — see only own 30/120, then "Failed to delete own files"; node2 passes. repro
tests/repro_blockdir_visib.sh (KEEP, 30 5, mkdir-by-test1 + concurrent create + sleep 1) reproduces
100%: EVERY node sees own 30/120, test2/3/4 rm-fail their own 30 (test1=creator deletes OK).
BUT a create-only variant with sleep 2 + drop_caches COLD read = ALL nodes see 120 warm AND cold →
**disk holds the merged 120; it is NOT an on-disk lost-update.** It's an intermittent per-node STALE
cached dir DATA block: dir inode 132 is coherent (fmt=2 size=4096 block, 1 extent) but the node
serves its own cached data block (only its 30 entries). dmesg floods P106-MR-SKIP (gen==evicted_gen
→ acquire-time evict already ran + stamped evicted_gen, so modify_refresh skips) → the acquire-time
mxfs_dir_drain_evict_data_blocks evidently did NOT FUA-re-read the peer's durable block (likely
skipped a transiently pinned/in-AIL block via XBF_TRYLOCK). Under CAW there is no BAST for a peer's
silent dir modify, so the reader relies entirely on acquire-time evict; when it skips, stale.
NEXT (RULE 4): instrument mxfs_dir_drain_evict_data_blocks on the uv dir — confirm it skips a
pinned/in-AIL data block; the rm-fail on test2/3/4 (can't delete OWN file) needs its own trace
(likely the unlink's dir-block RMW lookup fails off the stale base). Consider extending the
LSN/durability discriminator to dir-data blocks (xfs_dir3_blk_hdr.lsn) so the reader can detect
disk-newer and force a FUA re-read instead of skipping. Timing-sensitive: reproduce with sleep 1 +
mkdir-first; sleep 2 can mask it. Gemini's leaky-drain note (xfs_log_force(SYNC) before AIL push)
may also matter for dir release.

### Scripts (KEEP): repro_double_alloc.sh, repro_fua_always.sh (fua lever NOT the fix), repro_blockdir_visib.sh.
</body>
