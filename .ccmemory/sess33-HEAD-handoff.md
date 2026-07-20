---
name: sess33-HEAD-handoff
description: sess33 HEAD: DECISIVE — dir_reuse 799 loss-write IS the EX-release drain's xfs_bwrite (P-WMERGE-STACK: mxfs_dir_flush_one_daddr→xfs_bwrite, comm=dd).…
metadata:
  type: project
---

## sess33 HEAD — read first. CRITERIA NOT MET (1/2/4 tcp=100%; 8/tcp blocked by dir_reuse readdir=799).

### BUILD: /src/mxfs/mxfs.ko = 275EF4D4 = keeper-equiv. ALL sess33 fix params default-0 (dir_write_merge, dir_reflush_skip, dir_release_stale, dir_zombie_retire, dir_zombie_push). Diagnostics (P-WMERGE+stack, P-WGHOST, P33-LOGSTALE) gated behind dirwr/instr (off by default). Reboot → keeper behavior (799 loss). SAFE.

### ★ DECISIVE FINDING (P-WMERGE-STACK, dump_stack at the loss-write): the durable-loss write IS the EX-RELEASE FENCE DRAIN's synchronous bwrite:
```
xfs_buf_submit_bio (P-WMERGE: disk_extra=1 incore_extra=1)
 xfs_buf_submit  <- xfs_bwrite
 mxfs_dir_flush_one_daddr+0x201   (xfs/xfs_mxfs_dlm.c ~1751)
 mxfs_dir_flush_data_blocks
 ... (EX release path, comm=dd)
```
So Gemini was right: the zombie write is the release fence draining a dir block (Invariant #1) whose in-core image is a STALE BASE. `disk_extra=1` = the on-disk block has a dirent (a peer's prior-tenure add) our in-core block LACKS. We RMW'd our this-tenure adds onto that stale base (never saw the peer's add — bmap/block was stale at acquire), so our block = {stale_base ∪ our_adds} MINUS the peer's add. The release drain bwrites it → reverts the peer's add = durable 799. (We hold EX this whole tenure, so the missing dirent must be a peer's PRIOR-tenure add we never refreshed — our acquire-side stale-base refresh missed it.)

### WHY all retire/skip fixes failed (8 refuted, see [[sess33-fixes-refuted-zombie-bli-reenters-after-evict]] [[sess33-REFUTED-dir-write-merge-overgrafts-803]]):
- The loss is NOT a lingering-BLI reflush (GPT's model) — it's a STALE-BASE RMW written by the release drain. BLI-retire at acquire-evict / read-path / release-drain / iop_push ALL fire 0× (P33-*-RETIRE=0). DONE=0 in P-WMERGE is real (xfs_buf_submit does NOT clear DONE for writes) but the retire gates (!DONE/destaged) don't match at the drain (DONE/undestaged state there differs from submit-time).
- Write-side SUPPRESSION (skip) = drops legit writes (catastrophic readdir=0).
- The EXISTING union-merge `mxfs_dir3_data_writemerge` (graft disk-only dirents into our block, param dir_write_merge, xfs_buf.c ~2215 called from xfs_buf_submit ~3595) is the RIGHT idea (union loses neither add) but OVER-GRAFTS (readdir=803 +3 + leaf desync lookup_fail) — likely per-block dedup grafting a peer dirent into block X when it also lives in block Y.

### THE FIX (next session) — two angles, both at/around the PROVEN drain site:
1. **Acquire-side stale-base refresh is incomplete**: the block our this-tenure RMW used was a STALE BASE (missing a peer's prior add, disk_extra>0). The acquire-evict/read-path SHOULD have FUA-refreshed it before the RMW but didn't (P-POSTRMW historically showed superset, but that was a different block/timing). ROOT FIX: ensure EVERY dir data block is refreshed from the coherent LUN at EX acquire BEFORE any RMW, so our adds graft onto the peer's current image (union naturally). Check why disk_extra>0 survives to the drain — the acquire refresh (mxfs_dir_evict_data_blocks / xfs_da_read_buf gen-invalidation) is missing this block (stale bmap? gen not bumped? owned_ex gate?).
2. **Drain-side union-merge** (last line): in mxfs_dir_flush_one_daddr (xfs/xfs_mxfs_dlm.c ~1649, BEFORE the xfs_bwrite at ~1751), plain-read disk (release ctx can sleep, holds ILOCK); if disk_extra>0 (disk has dirents we lack), GRAFT them into our block before bwrite → write the union. This is the writemerge logic but at the drain (single block, locked, EX-held — cleaner than the async chokepoint). MUST fix the over-graft: dir-WIDE name dedup (don't graft a name present in ANY of our in-core dir blocks) + ensure the grafted dirent's leaf hash entry exists (or rely on datascan-heal). Use mxfs_dir3_disk_has_extra_inum + mxfs_dir3_data_graft_one (both in pal/linux/xfs_buf.c, non-static).

### Consults: GPT-5.5 ×2 + Gemini ×1 (on file). Gemini correctly predicted the release-fence drain as the writer.

### REPRO: `bash tests/tcp/drc_repro_loop.sh 6 "dir_writeprobe=1 dirwr=1" 24` (readdir=799, ~1/2 iters; probe amplifies). Capture P-WMERGE (loss-write state) + P-WMERGE-STACK (writer path). [[sess33-PROVEN-clean-inAIL-stale-reflush-not-ghost]] [[sess33-fixes-refuted-zombie-bli-reenters-after-evict]]
