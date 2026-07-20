---
name: sess19-holeA-ruled-out-fix-is-read-image-origin
description: sess19: GPT Hole A (acquire eviction misses high-offset leaf) RULED OUT — P-EVICT-SKIP fired for the leaf daddr (2093296) so eviction reaches it. The…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) — narrowing the [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]] implementation.

## GPT Hole A RULED OUT: the acquire-side evict (mxfs_dir_evict_data_blocks, for_each_xfs_iext over the data fork) DOES reach the leaf block. Evidence: in the iter14 short run the leaf1 was at daddr=2093296 (P16-DIRBLK-SUBMIT ops=xfs_dir3_leaf1 daddr=2093296), and P-EVICT-SKIP fired for `ino=131 daddr=2093296` — so the evict iext walk covers the high dir2 leaf offset (0x800000 logical maps into a normal data-fork extent; MXFS walks extents not i_size, so Hole A's i_size caveat doesn't apply). The evict SKIPPED it as done=0 (already !XBF_DONE) or undest=1 (kept). So coverage is fine; the bug is that the leaf gets re-populated/re-modified on a STALE base after eviction, within the tenure.

## THEREFORE the fix is GPT Hole B + the dirty/write enforcement, NOT eviction coverage: the per-buffer b_mxfs_dir_gen must be an IMAGE-ORIGIN epoch — set ONLY at read submit/completion (carry read-submit epoch through to completion so a late readahead/read that completes after the tenure advanced stamps the OLD epoch = stale), NEVER on cache-hit/touch/!XBF_DONE-prestamp/post-read-restamp (xfs_da_btree.c currently does these touch-restamps — that's the bug). Then a stale-image (b_mxfs_dir_gen != i_dlm_dir_gen) dir index buffer: if CLEAN → cold re-read; if DIRTY/PINNED → invariant violation (shutdown or rebuild-from-data-blocks under EX), NEVER silently keep+write (the current keep-guard keeping a gen-stale pinned leaf, then xfsaild flushing it, IS the clobber). Bio write-submit = final backstop (shutdown/diag on stale image; NOT a buf_cnt<disk_cnt skip — count is unsafe vs legit removes).

## QUICK PARTIAL CLOSE to try first (sess20): make xfs_da_reada_buf a no-op for dir index blocks on shared multinode mounts (kills the late-readahead stale repopulation = Hole B's main source) and audit every b_mxfs_dir_gen WRITE site in xfs_da_btree.c to ensure none stamp current on a cache-hit/touch. Then re-run cc_blockdir_probe 30 50 ×3 (0 short + all readdir entries lookup-able) + ./run.sh 2 tcp 16/16. If still failing, implement the full read-submit-epoch carry + dirty-time guard.

## STATE: build 8B8D7499 deployed (detectors P16+dgen/lgen/pmp, P-LEAFWRITECLOBBER, P-LEAFREADSTALE; mxfs_dir_skip_info has dir_gen/loaded_gen). Cluster clean, dirwr=0, mounted, official ./run.sh 2 tcp=16/16. Marker NOT written. [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]] [[sess19-PROVEN-xfsaild-stale-leaf-reflush-clobber]]
