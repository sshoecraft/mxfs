---
name: sess13run-MHT-invariant-residual-leading-hypo-LIO-writeback-vs-FUA-platter-revert
description: sess13(ccloop) residual 399/400 INVARIANT across MHT(300/2000), FUA, epoch, cohmod, release-invalidate. Leading hypo: fua_always FUA-reads PLATTER, m…
metadata:
  type: project
---

## sess13 (ccloop) — residual is MHT-invariant; leading hypothesis = LIO write-back vs FUA-platter read

### Robustness of the residual (all build 3091C841 / winning config + one extra lever)
dir_reuse 4/tcp = exactly 399/400 (1 durable dirent lost), NO shutdown, under EVERY tested variant:
- inode_mht_ms=300 (default), =2000 → 399. =0 → WORSE (318). So MHT>0 is needed but tuning it does NOT close the residual.
- +dir_coherent_modify=1 → 399 (COHMOD-INVAL=0). +dir_release_invalidate=1 → 399 (P-RELINVAL fired ~0-4x).
The residual is a single, robust, deep race — not sensitive to handoff frequency or read/evict coherency levers.

### LEADING HYPOTHESIS (next to test): LIO write-back cache vs FUA-read-to-platter REVERT
Directionality (sess11run, PROVEN): the LATER writer's just-placed dirent REVERTS to the disk image (dropped). With `fua_always=1`, EVERY metadata read (incl. a node's force-evict re-read of a dir block it ITSELF just modified) is a SCSI READ(16) FUA that pierces to the PLATTER. But mxfs considers a dir block "destaged/durable" (written_seq>=logged_seq, undestaged=false) once it is SUBMITTED to the LIO TARGET — which on LIO lands in the target's WRITE-BACK cache, NOT necessarily the platter. So:
1. Node writes dirent E1 into block B → B submitted to LIO (in target write-back cache), mxfs marks B destaged/durable.
2. Same node's NEXT create runs force-evict; B is now "clean+durable" (not undestaged) → evicted → FUA re-read.
3. The FUA read goes to the PLATTER, which LACKS E1 (still only in LIO write-back cache) → in-core B reverts to the pre-E1 image → E1 durably lost when B re-flushed.
This explains why: FUA fixed the READ-stale corruption but introduced/left a WRITE-not-yet-on-platter revert; why coherent_modify (count compare) and release-invalidate (clean-durable) don't catch it (B's block IS "durable" by mxfs's LIO-submit notion); and why it's exactly 1 entry (the rare interleave where a just-written block is FUA-re-read before its platter destage).

### NEXT TEST (RULE 4): make a dir block's "durable" mean PLATTER-durable, not LIO-submit.
Options: (a) after writing dir DATA blocks (release fence mxfs_dir_flush_data_blocks already does xfs_bwrite; ADD a blkdev_issue_flush right after the per-block xfs_bwrite, before marking destaged — forces platter), AND ensure intra-tenure xfsaild destages also flush; OR (b) the force-evict / mxfs_dir_buf_is_undestaged must treat a block as "still mine, do NOT FUA-re-read" until a platter flush has occurred (track a platter-durable seq distinct from the LIO-submit written_seq); OR (c) for own-recently-written dir blocks, read the LIO cache (non-FUA) instead of platter FUA — but that reintroduces peer-stale risk, so scope to "block this node wrote since the last platter flush". 
Cheapest first probe: at the force-evict re-read of a dir block, log whether the FUA-read content count < the in-core count (i.e. the platter is BEHIND our in-core) — if it fires on the loser, hypothesis CONFIRMED. Then add a post-write blkdev flush.

### Build 3091C841 (inert dir_release_invalidate param, default off). Winning config: fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1 → 399/400. RULE-0: fua_always too slow, scope later. See [[sess13run-FIX-ATTEMPT-release-invalidate-inert-culprit-is-dirty-durable-AIL-buffer]] [[sess11run-DIRECTIONALITY-later-writer-stale-bestfree-loses-fix-coherent-refresh]].</body>
</invoke>
