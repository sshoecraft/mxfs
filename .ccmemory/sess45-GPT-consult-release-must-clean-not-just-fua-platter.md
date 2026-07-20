---
name: sess45-GPT-consult-release-must-clean-not-just-fua-platter
description: sess45 GPT-5.5 consult (RULE-5): KEY insight — raw SCSI FUA at release makes the PLATTER current but leaves XFS buffer DIRTY/in-AIL, so addname_coher…
metadata:
  type: project
---

## sess45 GPT-5.5 consult — the dirty-block double-alloc fix

### THE KEY INSIGHT (what I missed):
dir_release_fua_write (raw SCSI WRITE16+FUA) makes the PLATTER current but XFS's
in-core buffer can remain DIRTY/in-AIL/pinned after release. So at the next EX
acquire the node STILL has a dirty/in-AIL stale buffer; addname_coherent (the
reader-side reread) correctly SKIPS dirty/in-AIL blocks (to protect own work) →
the node RMWs the stale base → intra-block double-alloc. We made the platter
current but NOT the local XFS buffer state clean. (We DO xfs_bwrite before the
FUA, which cleans the buffer, but the BLI LINGERS IN THE AIL — sess37 — and
addname_coherent skips in-AIL blocks.)

### THE FIX (GPT, ranked safest):
1. **DLM EX RELEASE must be a synchronous XFS metadata checkpoint boundary**: for
   EVERY dir DATA/LEAF/FREE block touched, log-force → unpin → xfs_bwrite(+FUA) →
   wait IO → ensure NOT dirty/pinned/in-AIL → invalidate (mark not-current) →
   THEN dlm_unlock. The existing release path FUAs the bytes but leaves the BLI
   in-AIL. => enable BLI retirement at release. Lever EXISTS:
   dir_release_retire_bli (xfs_mxfs_dlm.c:4143, default 0; retires the in-AIL BLI
   after the proven-durable xfs_bwrite). dir_release_invalidate=1 already default
   (stale+clear XBF_DONE). sess39 refuted retire_bli (readdir=796 over-lost) BUT
   that was BEFORE dir_release_fua_write — the retired block's platter image was
   STALE then; NOW the FUA forces the platter current so retiring is safe.
   TESTING NOW: batch8_retirebli.log (dir_release_retire_bli=1 on build FB296422).
2. **DLM EX ACQUIRE = coherency boundary before first modify**: cold-read the
   current platter for the inode dinode + every dir block before any free-space
   decision, UNLESS the object was already modified THIS tenure (per-tenure tag:
   bp->dirty_seq == grant_seq → keep; else refresh). If dirty but NOT
   modified-this-tenure → it's stale leftover → must refresh (release should have
   cleaned it; if still dirty after a peer handoff = protocol violation).
3. **Sub-case (a) data_init-zeroes-block0**: before xfs_dir2_sf_to_block converts,
   FUA-read the dinode; if disk di_gen == in-core i_generation AND disk di_format
   != LOCAL (peer already converted to block/leaf), the in-core shortform fork is
   STALE → reload inode + restart (do NOT data_init/zero block0). di_gen
   disambiguates incarnations (the on-disk dir block header has owner but NO
   generation, so block-level content can't distinguish rounds; di_gen can).
   Do the reload OUTSIDE the live trans (at the DLM acquire wrapper); use a guard
   in sf_to_block as last-chance (return EAGAIN/restart).

### DO NOT: union-merge dir blocks (offset/bestfree/hash/leaf must all agree —
prior attempts corrupted) or wholesale-adopt-disk over dirty (rolls back own work).

### UNIFYING INVARIANT: "the first modify of any dir metadata object in an EX
tenure must be based on a coherent post-grant disk read, unless modified earlier
this tenure." Release makes it clean; acquire cold-reads; same-tenure dirty is
safe; prior-tenure dirty is illegal.

### Full GPT reply saved in this session transcript. Code sites: release hook
(mxfs_dir_flush_data_blocks / mxfs_dir_flush_one_daddr ~2337 where retire_bli
lives), acquire (mxfs_dlm_reload_inode + addname_coherent), xfs_dir2_sf_to_block.
See [[sess45-BREAKTHROUGH-8node-loss-is-intrablock-doublealloc-addname-coherent-fix]]
[[sess45-WINNING-config-and-remaining-work]] [[sess61-FINAL-dirty-keep-guard-in-drain-evict-is-the-gap]].
