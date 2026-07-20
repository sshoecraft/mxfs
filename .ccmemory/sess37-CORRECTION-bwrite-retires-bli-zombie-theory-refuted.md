---
name: sess37-CORRECTION-bwrite-retires-bli-zombie-theory-refuted
description: sess37 CORRECTION: xfs_bwrite DOES retire the BLI (__xfs_buf_ioend:1387 → xfs_buf_item_done = ail_delete+relse). Zombie-BLI theory & delwri lead REFU…
metadata:
  type: project
---

## sess37 CORRECTION — refutes the zombie-BLI-reflush theory (sess32/33) and the delwri lead.

### PROVEN by code (pal/linux/xfs_buf.c):
- `__xfs_buf_ioend` line ~1320 `} else {` is the WRITE-completion branch; line 1387 `if (bp->b_log_item) xfs_buf_item_done(bp);`.
- `xfs_buf_item_done` (pal/linux/xfs_buf_item.c) = `xfs_trans_ail_delete(bli)` + `xfs_buf_item_relse(bli)` → REMOVES from AIL AND FREES the BLI.
- `xfs_bwrite` = xfs_buf_submit + xfs_buf_iowait (WAITS for completion). So by the time the release-drain bwrite returns, `__xfs_buf_ioend` has ALREADY retired+freed the BLI.

### THEREFORE:
1. **The release-drain bwrite DOES retire the BLI** (contradicts the sess32 "xfs_bwrite does NOT retire the BLI" claim — that was wrong). No zombie BLI survives the release path.
2. **sess37 `dir_release_retire_bli` corrupted because it was a DOUBLE xfs_buf_item_done** (the ioend already called it) → use-after-free → "Metadata I/O Error" shutdown. NOT because BLI-retire is inherently bad.
3. **The delwri-submit lead is MOOT**: xfs_buf_delwri_submit and xfs_bwrite share xfs_buf_submit + the same __xfs_buf_ioend completion (line 1387), so delwri would retire the BLI identically — no improvement. Do NOT pursue the delwri-release refactor.

### SO WHAT IS THE LOSS? (refocused)
The clobbering write (P-DATACLOBBER: in_ail=1, has a BLI, bgen=0/stale=1, genuine EX) is NOT a leftover zombie — it is a buffer **freshly modified (RMW) THIS tenure on a STALE base**, committed (fresh BLI in AIL), then written by xfsaild/release. Reads ARE coherent (P28-PLATTER 7152 MATCH) BUT only for blocks that go through addname's READ path (xfs_da_read_buf). The stale-base RMWs are on blocks reached via a **get_buf / non-read modify path** that uses the cached b_addr WITHOUT re-reading: after grant_evict clears XBF_DONE + sets bgen=0, the b_addr still holds the PRIOR-tenure content (e.g. a leaf with 117 entries); if the next modify uses xfs_da_get_buf (no read) or otherwise operates on b_addr without an xfs_da_read_buf re-fetch, it RMWs the stale 117 image and writes it over disk's 379 → loss. bgen=0 on the clobber = the block was evicted (XBF_DONE cleared) but MODIFIED before any read re-populated b_addr.

### NEXT (refocused, the real angle):
Find dir modify paths that operate on an evicted (XBF_DONE=0, bgen=0) buffer's b_addr WITHOUT an xfs_da_read_buf re-fetch — i.e., xfs_da_get_buf callers used for MODIFY (not pure fresh-alloc-init) at a reused daddr. Candidates: leaf/node conversion+split (xfs_dir2_block_to_leaf, leaf_to_node, node split), freeindex (xfs_dir2_free) get_buf, and any path that reuses a cached buffer post-evict. The fix: such a path must xfs_da_read_buf (coherent re-fetch) the block before RMW when the cached buffer is XBF_DONE=0/bgen<dir_gen, OR grant_evict must not just clear XBF_DONE but force the re-read to complete. INSTRUMENT: at the clobber (dataclobber=1), capture the STACK (dump_stack) of the modify that produced the stale b_addr (which get_buf/read path), to pinpoint the exact call site. This is the decisive next probe — do not guess the call site.

### Standing negatives unchanged: write-side DROP/suppress of dir DATA = corruptor (5×); content-compare → ghost wall. Build DFAEAF39 keeper-equiv at default. Best config ~50% (read-side stack + zombie retires). See [[sess37-HEAD-handoff]] [[sess37-REFUTED-release-retire-bli-and-readside-coherent]].
