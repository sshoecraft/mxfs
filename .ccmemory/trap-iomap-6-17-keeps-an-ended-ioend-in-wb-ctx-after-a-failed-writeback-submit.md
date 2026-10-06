---
name: trap-iomap-6-17-keeps-an-ended-ioend-in-wb-ctx-after-a-failed-writeback-submit
description: TRAP (0.90.73, proven): from 6.17 iomap_add_to_ioend returns a ->writeback_submit error with wb_ctx still the ended ioend; next folio resubmits it →…
metadata:
  type: feedback
---

From Linux 6.17 the iomap writeback context's in-progress ioend lives in `wpc->wb_ctx`, owned by the filesystem's `->writeback_submit`. iomap never clears it:

- `iomap_add_to_ioend` (fs/iomap/ioend.c): when the cached ioend cannot take the next folio it calls `->writeback_submit(wpc, 0)`; on an error it `return error` with `wb_ctx` still pointing at the ioend just ended (on success it overwrites `wb_ctx` with a new ioend at once).
- `iomap_writepages` (fs/iomap/buffered-io.c): a WB_SYNC_ALL pass (fsync) keeps going after a folio error, and at the end `if (wpc->wb_ctx) return ->writeback_submit(wpc, error)`.

So an error returned mid-pass makes iomap hand the SAME ended ioend back for every later folio and once more at the end. `iomap_ioend_writeback_submit(wpc, err)` ends it via `bio_endio` each time → double completion / double free. Before 6.17, `iomap_submit_ioend` set `wpc->ioend = NULL` itself, so the pre-6.17 `->prepare_ioend` path is safe.

**Measured (0.90.73, nested PVE 9.1 pair, 6.17.2-1-pve):** `tests/pve_wb_refusal.sh` refused the first ioend of an fsync via `dbg_refuse_data_n`; `P294-WB-ENDED-IOEND-AGAIN` fired with the same hashed ioend pointer, the ioend was refused again, then `kernel BUG at mm/slub.c:563` + page fault in `iomap_finish_folio_write`. On the physical pair (0.90.72) one ioend was refused 11 times during a withdrawal and fsync hung on a folio lock nobody held (D-DRBD-WITHDRAWAL-UNDER-WRITEBACK-LEAVES-A-FOLIO-LOCKED-FSYNC-HANGS).

**How to apply:** any 6.17+ `->writeback_submit` must clear `wpc->wb_ctx` after handing the ioend to `iomap_ioend_writeback_submit` (MXFS: `mxfs_ioend_hand_off` in pal/linux/xfs_aops.c). Any new refusal/error return added to that hook must go through it. Upstream XFS's own COW-conversion error in `xfs_writeback_submit` has the same exposure.
