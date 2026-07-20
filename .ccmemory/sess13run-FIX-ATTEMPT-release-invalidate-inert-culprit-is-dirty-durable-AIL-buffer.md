---
name: sess13run-FIX-ATTEMPT-release-invalidate-inert-culprit-is-dirty-durable-AIL-buffer
description: sess13(ccloop) GPT Option-1 release-invalidate (build 3091C841, param dir_release_invalidate, default 0) = INERT (fired 0-4x/node, still 399/400). Cu…
metadata:
  type: project
---

## sess13 (ccloop) — GPT Option-1 (release-side buffer purge) implemented, INERT

### What was built (build 3091C841, KEPT, default OFF — harmless)
New param `dir_release_invalidate` + helper `mxfs_dir_release_invalidate_data_blocks` (xfs_mxfs_dlm.c, called in mxfs_dlm_bast_process right after the H26 pre-unlock blkdev flush, under down_read(i_lock)). Walks the dir extent map and clears XBF_DONE|_XBF_FUA_FRESH + zeroes b_mxfs_dir_gen on each cached dir block that is PROVABLY clean+durable (not dirty/in-AIL/pinned/delwri/undestaged). Goal (GPT-5.5 Option-1): "no dir DATA buffer survives an EX handoff" → next acquire cold-reads coherent.

### RESULT: INERT. `fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1 dir_release_invalidate=1` → STILL 399/400, no shutdowns. P-RELINVAL fired only 0-4x/node across 20 rounds (test2/test4 = 0). So almost no release had a clean+durable cached dir block to invalidate.

### WHY inert → sharpens the diagnosis
The safety guard SKIPS dirty / in-AIL / undestaged buffers (to protect own uncommitted work + avoid the "clear XBF_DONE on dirty buf = CORRUPT_INCORE shutdown" trap). The fact it almost never fired means at release the dir blocks are NOT clean-XBF_DONE — they are DIRTY-but-durable: `XFS_LI_IN_AIL` set (in AIL for log-tail tracking) but data already written (written_seq >= logged_seq). That is EXACTLY the buffer GPT-5.5 said must be discarded — but clearing XBF_DONE on an in-AIL/dirty buffer is the sess96-refuted force-evict-on-release that resurrects/corrupts. So the safe version can't touch the culprit.

### Two viable next directions (both harder):
1. GPT Option-2 (epoch-stamp): add per-buffer `grant_epoch` stamped at read/modify; on a dir modify, if buf.epoch < current grant epoch AND buf is durable (written_seq>=logged_seq), AIL-SAFELY invalidate (xfs_buf_stale / detach from AIL via xfs_trans-free path, NOT raw XBF_DONE clear) then re-read. Requires correct AIL manipulation = high risk.
2. RE-EXAMINE directionality: sess11run proved the LATER writer's in-core REVERTS to disk (its just-placed dirent dropped). "Reverts to disk" = an EVICT/reload fired AFTER placement but BEFORE durability, re-reading disk (which lacks the just-placed entry) over the in-core change. Hunt for an invalidation/reload that can fire mid-create-RMW (epoch-adopt? a concurrent peer's note_dir_modified bumping dir_gen → modify-path force-evict on the NEXT addname re-reads and drops the previous addname's not-yet-durable entry?). If a same-tenure 2nd addname's force-evict reverts the 1st addname's undurable entry, the fix is to NOT evict a block carrying this tenure's own uncommitted adds (which the undestaged-skip SHOULD do — verify it actually covers the just-added entry's block).

### Still 399/400 best; fua_always too slow (RULE-0). Build 3091C841 has the inert lever (off by default). Winning config unchanged. See [[sess13run-FINAL-residual-is-concurrent-sameblock-rmw-cohmod-skips-own-undestaged]] [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>
