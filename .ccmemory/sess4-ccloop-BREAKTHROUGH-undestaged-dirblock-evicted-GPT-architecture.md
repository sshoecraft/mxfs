---
name: sess4-ccloop-BREAKTHROUGH-undestaged-dirblock-evicted-GPT-architecture
description: sess4(ccloop run6614) BREAKTHROUGH + GPT-5.5 consult: the force_block/dir_reuse shutdown = a committed UNDESTAGED dir block0 (content only in-core; d…
metadata:
  type: project
---

## sess4 (run 6614aa96) — PROVEN mechanism of the dir-block shutdown + GPT-5.5 architectural fix

### PROVEN CHAIN (probes across xfs_da_btree.c / xfs_dir2_block.c / pal/xfs_buf.c; builds culminating C7C10753)
1. Multinode dir data BLOCKS are NEVER written by xfsaild (P16-DIRBLK-SUBMIT count=0 whole run) — by design, they destage ONLY via the DLM release-drain when EX is released/BAST'd (background write could clobber a peer's dirent).
2. A self-created, EX-held dir (force_block=1 → sf→block; or dir_reuse@fb0 churn) get_buf-inits block0 at low daddr (112/120), commits. In-core extent map == disk dinode map, same gen (NOT divergent). Disk block content = never written = all-0xFF (thin LUN).
3. P-RDPATH: at T0 the block0 buffer is `in_cache=1 DONE=1 in_ail=1 undest=1` (committed-unwritten, authoritative in-core). ~1.5ms later (same daddr): `inc_rc=-ENOENT` = GONE from cache.
4. P-DIRFREE: the free happens DURING a read — `xfs_buf_read_map→xfs_buf_rele→xfs_buf_free`, buffer has valid XDB3 content but `has_bli=0` (BLI already retired). = xfs_buf_get_map PURGES a cached buffer that was marked XBF_STALE, then re-reads disk → 0xFF → xfs_dir3_block_verify EFSCORRUPTED → `xfs_trans_read_buf_map` shutdown.
5. P-DIRSTALE (undest=1) did NOT fire → when block0 was staled+BLI-retired, it was already considered `undest=0` (destaged) and `in_ail=0`. But it was NEVER written (P16=0). **So the undestaged→destaged transition happened WITHOUT a write** — the release-drain (or mxfs_dir_zombie_push_retire) marked block0 destaged and retired its BLI without actually flushing it to disk. That is the ROOT BUG.

### GPT-5.5 CONSULT (RULE 5, complete diagnosis + 1 refuted fix): key points
- Confirmed: a committed dirty metadata buffer with a BLI in the AIL must NOT be reclaimable before its home-block write completes; a buffer vanishing while logically undestaged is an MXFS lifecycle violation. `b_lru_ref` is not the correctness primitive — need a real buffer hold.
- SOUNDEST fix (GPT Option B): allow xfsaild/AIL writeback of dir blocks WHILE the node owns the current EX epoch (no peer can concurrently modify under our EX), and make DLM release-drain WAIT for all in-flight dir writes before unlock. Don't gate on "no BAST pending" — until we actually unlock we still own the epoch; if a write is in flight when a BAST arrives, the drain waits for it. This keeps disk current so eviction is harmless, and preserves Invariant 1.
- DEFENSIVE fix (GPT Option A): xfs_buf_hold() every dir buffer when it becomes undestaged, attach to an inode/epoch list, xfs_buf_rele() at release-drain write completion — so it can never be LRU/purge-freed while its content is the only copy. Must NOT replace BLI/AIL correctness (crash consistency).
- Immediate: never retire/stale/clean the BLI of an undestaged dir buffer until its home-block write completes.

### NEXT SESSION — implement + verify (fast repro: `./run.sh 2 tcp cache_coherency` @DEFAULT force_block=1, mostly-fails ~30-60s; or `scripts/drc_reliability.sh 4 5 dir_force_block=0`)
1. FIND the site that marks block0 destaged + retires its BLI without a write: instrument `xfs_trans_ail_delete` / `xfs_buf_item_done` / `xfs_buf_item_unpin` / the release-drain dir flush (drain_meta_buffers / mxfs_dir_zombie_push_retire) for daddr 112/120 — who clears undestaged without an I/O.
2. Then fix: either (B) epoch-gated dir writeback under EX + drain-wait, or (A) defensive undestaged-dir-buffer hold, or fix the drain's false "destaged" marking.
### Probes in build C7C10753 (harmless, ratelimited/capped): P-DIFREE-*, P-BLKRV-*, P-BLKLK, P-DBLALLOC-BIRTH, P-BLKWR, P-RDPATH, P-DIRSTALE, P-DIRFREE.
### CONFIG (settled): run force_block=0 (2/tcp=17/17). This bug also blocks force_block=1 cache_coherency AND dir_reuse@fb0 4/8.
See [[sess4-ccloop-HANDOFF-full-column-status-and-next-step]] [[sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root]] [[sess4-ccloop-MILESTONE-2tcp-17of17-at-forceblock0-config-decision]]
