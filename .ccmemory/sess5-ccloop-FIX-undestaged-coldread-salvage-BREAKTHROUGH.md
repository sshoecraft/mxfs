---
name: sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH
description: sess5(run6614) BREAKTHROUGH FIX (build F8444712): undestaged dir-block cold-read SALVAGE in xfs_da_read_buf → cache_coherency 2/tcp @ force_block=1 P…
metadata:
  type: project
---

## sess5 (run 6614) — PROVEN FIX: undestaged cold-read salvage

Build **F8444712** (xfs_da_btree.c). `./run.sh 2 tcp cache_coherency` @ DEFAULT force_block=1 → **PASS 2/2** (was deterministic FAIL 0/2 for ~50 sessions).

### Root (RULE-4 proven this session)
Multinode dir DATA blocks are UNDESTAGED (destage only at DLM release, P16=0). A freshly-created/REUSED dir block0 (its on-disk daddr still holds a FREED prior owner's un-zeroed dir3 block, or garbage on a never-written block) lives only in-core. One of the ~10 XBF_DONE-clearing sites (evict/reload/modify-refresh) clears DONE on that undestaged buffer; `xfs_da_read_buf` then COLD-READS the stale disk → `xfs_dir3_block_verify` owner-mismatch/CRC → shutdown. PROVEN: ino=132 daddr=112 read back garbage owner=0x91..; ino=2097281 daddr=2093344 read back foreign owner=2097280 (block freed from 2097280, disk_nlink=0, reallocated to 2097281 but stale content never zeroed).

### The fix (xfs_da_btree.c, in the in-core-invalidated branch ~line 3302)
When incore finds the dir DATA buffer with XBF_DONE cleared, and it is UNDESTAGED (payload-LSN this-node-ahead) AND its in-core header owner == this inode AND not XBF_STALE AND b_addr live → RESTORE XBF_DONE and serve the in-core content instead of cold-reading disk. Raw DONE-clear sites don't stale the buffer, so b_addr is intact; our in-core copy is the ONLY authoritative one. Scoped multinode dir only. Probe: P5-UNDEST-SALVAGE.

### DISPROVEN this session (RULE 4): Fix A alone — dropping the `!in_ail` term from the xfs_da_btree keep-guard bypass (line 3457) did NOT fix it (build AB674659, still FAIL). P-RDPATH showed the buffer arrives at the read with DONE ALREADY 0 (cleared by an earlier site), so the keep-guard (requires DONE=1) never runs. Fix A is KEPT (harmless, complements the salvage) but insufficient alone.

### Diagnostic probe added (harmless): P-DBLALLOC-AGF in xfs_dir2_data.c (FUA AGF free-space compare at foreign-birth). Confirmed disk AGF shows the live block FREE (genuine block-reuse, not a simple read-staleness).

### NEXT: confirm cache_coherency@fb1 reproducible (3×), run FULL 2/tcp suite for regressions, then 4/tcp + 8/tcp. If clean, this may unblock ALL columns at BOTH force_block settings.
See [[sess5-ccloop-MEASURED-dblalloc-birth-fires-forceblock1-2tcp]] [[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]]
