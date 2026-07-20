---
name: sess26-target-flush-refuted-clobber-is-xfsaild-push-of-invalidated-buffer
description: sess26(ccloop): FUA-platter-lag REFUTED (dir_modify_target_flush=1 SYNC-CACHE before RMW read still loses readdir=799). Refined hypothesis: clobber =…
metadata:
  type: project
---

## sess26 — FUA-platter-lag refuted; clobber locus = xfsaild push of invalidated in-AIL buffer

Builds on [[sess26-DECISIVE-evict-always-evicts-base-is-postevict-stale-read]].

### Tree state
Build **A04C8631** = 5954F53F keeper + 2 INERT default-0 levers (`dir_newtenure_evict`, `dir_modify_target_flush`) + field `i_dlm_dir_evict_mep` (xfs_inode.h) + P26 probe. Functionally KEEPER, NO regression. 1/2/4 tcp unaffected.

### Refuted: FUA-platter-lag
`dir_modify_target_flush=1` (NEW lever): after the modify-path evict, blkdev_issue_flush (SYNCHRONIZE CACHE) the shared target so a peer's drained dirent (parked in target write cache) reaches the PLATTER before the post-evict FUA read. → STILL FAILS (readdir=799, single durable loss round 3; 353s = flush not catastrophically slow). So the peer's release-drain DID land on the platter; the stale RMW base is NOT a FUA-vs-write-cache lag. REFUTED.

### Converging mechanism (sess25 + sess26 evidence)
1. Modify-path evict (mxfs_dir_evict_data_blocks, dir_force_evict=1 default) ALWAYS evicts cached DONE blocks incl. in-AIL (sess26 P68: zero undurable=1 in_ail=1). It clears XBF_DONE on the buffer but does NOT cancel the in-AIL BLI.
2. sess25 PROVEN: the clobber WRITE is the EX holder's own xfsaild AIL-push (mode=5/EX, in_ail=1, bdirty=0, comm=dd/bash), stale=0, EQUAL-count DIFFERENT-fingerprint.
3. sess33 known trap (xfs_da_btree.c comment): clearing XBF_DONE on a dirty/in-AIL buffer lets xfsaild bwrite the STALE INVALIDATED image over the peer's newer durable block (crc-lineage stale-write war) — the evict's own XBF_DONE-clear leaves b_addr holding stale bytes; if xfsaild pushes the still-in-AIL BLI BEFORE any access re-reads the buffer, it destages the stale b_addr → clobber.
4. WHOLE-BLOCK loss observed (round10 node1_f1..f16 = one data block reverted) fits: a node's lingering stale in-AIL copy of block0 destaged over a peer's fuller block0.

### NEXT HYPOTHESIS (RULE-4, for next session)
The clobber = xfsaild iop_push writing a dir buffer whose XBF_DONE was cleared by the modify-evict (invalidated, stale b_addr) while its BLI lingers in-AIL. TEST: instrument the dir-block iop_push (pal/linux/xfs_buf_item.c, where dir_ail_defer lives) to log when it pushes a multinode dir buffer with !XBF_DONE (invalidated) or b_mxfs_dir_gen==0 — does it fire at the loss round on the lost daddr? If yes, FIX = in iop_push, when a multinode dir buffer is !XBF_DONE (evict-invalidated), do NOT write the stale b_addr: either (a) re-read the coherent image first then write, or (b) skip the I/O but cleanly complete the AIL item (content is durable on disk; but completing an in-AIL item w/o write is the hard part — sess25 defer pinned the log). Alternatively the evict must NOT clear XBF_DONE on a still-in-AIL buffer (leaves xfsaild a stale image); instead force an immediate coherent re-read into b_addr so any later push is fresh. AVOID: the sess25 defer (XFS_ITEM_LOCKED) pinned the log tail → DLM starvation shutdown.

### Dead ends this session: MHT tuning (band-aid, not 100%), dir_tenure_evict (readdir=0), dir_newtenure_evict (readdir=0, in-AIL-undestaged XBF_DONE-clear corrupts), dir_modify_target_flush (FUA-platter-lag refuted). [[sess25-FIX-ail-defer-reduces-dir_reuse-loss-residual-remains]]
