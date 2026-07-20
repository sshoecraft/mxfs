---
name: sess4-ccloop-REFUTED-levers-and-BLI-retire-is-next-target
description: sess4(ccloop run6614) REFUTED 3 levers for the undestaged-dirblock-evicted shutdown: dir_ail_defer(=0 default, already off), dir_wseq_at_completion=1…
metadata:
  type: project
---

## sess4 (run 6614aa96) — refuted fix levers; the BLI-retire is the unfound root

### REFUTED this session (all still FAIL cache_coherency@force_block=1, 0/2-3)
1. `dir_ail_defer=0` — it's ALREADY default 0 (the AIL push-defer hook is off), so deferral is not why dir blocks aren't written. No effect.
2. `dir_wseq_at_completion=1` — defers the b_mxfs_written_seq stamp to real bio completion (so a skip-emulated write can't falsely mark a block destaged). Did NOT fix → the false-destage is not (solely) via the submit-time write_seq stamp at pal/xfs_buf.c:4394.
3. Read-path keep-guard change (xfs_da_btree.c: keep undestaged blocks regardless of in_ail) — INERT, because at the failing read the buffer is already a TRUE cache MISS (inc_rc=-ENOENT), not an in-core invalidate. Reverted.

### WHERE THE EVICTION ACTUALLY IS (narrowed)
- P-DIRFREE: block0 is freed DURING a read (`xfs_buf_read_map→xfs_buf_rele→xfs_buf_free`), buffer has valid XDB3 content but `has_bli=0` — its BLI was ALREADY retired. So `xfs_buf_get_map` purges a cached buffer marked XBF_STALE, then re-reads disk → 0xFF.
- P-DIRSTALE (my probe in xfs_buf_stale, gated undest||in_ail + dir magic) did NOT fire for block0 → when it was staled, it had undest=0 (written_seq==logged_seq: falsely destaged) AND in_ail=0 (BLI already retired).
- So the sequence is: BLI retired (in_ail 1→0) + written_seq bumped (undest 1→0) WITHOUT a real write (P16=0, disk 0xFF) → xfs_buf_stale (P-DIRSTALE misses it, undest=0) → get_map purge on next read → cold-read 0xFF → shutdown.

### NEXT SESSION — the ONE decisive instrument (GPT-5.5's explicit list)
Probe the BLI-retire / AIL-delete path for block0's daddr (112/120): `xfs_trans_ail_delete`, `xfs_buf_item_done`, `xfs_buf_item_unpin`, `xfs_buf_item_release`, and the RELEASE-DRAIN dir flush (xfs_mxfs_dlm.c ~2409 `werr=xfs_bwrite(dbp)` + the sess37 "missing BLI retirement at release-drain" + xfs_buf_stale right after). Find who retires the BLI and bumps written_seq WITHOUT the bio actually landing on daddr 112/120. STRONG suspect: the release-drain path xfs_bwrite(dbp) at low daddr — does the bio actually target daddr 112/120 (+ bt_sector_offset envelope), or is it skipped/misdirected? Also check the 3rd written_seq site behavior. Then apply GPT Option A (xfs_buf_hold on undestaged dir bufs, rele at real write completion) or Option B (epoch-gated xfsaild writeback under EX + drain-wait).

### Tree: build C7C10753 = probes ONLY (P-DIFREE-*, P-BLKRV-*, P-BLKLK, P-DBLALLOC-BIRTH, P-BLKWR, P-RDPATH, P-DIRSTALE, P-DIRFREE); the da_btree keep-guard fix was REVERTED. force_block=0 config unchanged (2/tcp=17/17).
See [[sess4-ccloop-BREAKTHROUGH-undestaged-dirblock-evicted-GPT-architecture]] [[sess4-ccloop-HANDOFF-full-column-status-and-next-step]]
