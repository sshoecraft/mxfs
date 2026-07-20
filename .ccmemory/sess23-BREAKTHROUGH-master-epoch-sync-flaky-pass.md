---
name: sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass
description: sess23(ccloop) BREAKTHROUGH build B17FED9A: dir_tenure_evict=1 (modify-evict epoch override + master-epoch valid_epoch sync + GPT-9.1 release undesta…
metadata:
  type: project
---

## sess23 (ccloop) BREAKTHROUGH — dir_reuse 8/tcp FLAKY PASS

Build **B17FED9A** (param `dir_tenure_evict`, DEFAULT 0). This is the CLOSEST any session has gotten: dir_reuse 8/tcp went from the deterministic 2-entry durable loss (r14 node6_f1.md5 + r24 node5_f1.md5, keeper) to a **FLAKY PASS** — passed clean 8/8 once, otherwise loses ONE entry at a random round (r10 node7_f29.md5; r17 node3_f35.md5), **NO shutdown/cascade ever**. CRITERIA STILL NOT MET (needs 100%).

### What dir_tenure_evict=1 enables (all gated, keeper inert at default)
Three coordinated changes in xfs/xfs_mxfs_dlm.c:
1. **MODIFY-EVICT epoch override** (mxfs_dir_evict_data_blocks, ~line 2870, probe P23-TENURE-EVICT): evict a cached dir DATA block whose `b_mxfs_dir_epoch < i_dlm_dir_valid_epoch` (clean/!dirty/!pin/!delwri/DONE), overriding the in-AIL-undestaged keep-guard. This is the EVICT-only half of the refuted `dir_evict_prior_tenure` (whose SHUTDOWN comes from its OTHER half — the read-path epoch_stale at xfs_da_btree.c:3333 clearing XBF_DONE on in-AIL during PR reads — GPT §8). Modify-evict runs under our own EX hold → safe, NO shutdown.
2. **master-epoch valid_epoch SYNC** (mxfs_dir_evict_data_blocks, right after the fmt guards): `i_dlm_dir_valid_epoch = max(valid_epoch, mxfs_v5_dlm_inode_dir_epoch(master))` before the per-block compare. valid_epoch LAGS (set late in reload), so b_epoch==valid_epoch even after a real handoff → the override UNDER-FIRED (the residual). The master epoch advances reliably per handoff; monotonic-max sync makes the override fire on genuine prior-tenure blocks WITHOUT over-evicting current work (master can't advance mid continuous-hold). THIS sync turned the deterministic 1-entry residual into a flaky-rare one.
3. **GPT-9.1 release undestaged-clear** (mxfs_dir_flush_data_blocks, after xfs_bwrite werr==0): `b_mxfs_written_seq = b_mxfs_logged_seq` so a relogged-after-drain block (GPT 9.3) isn't falsely kept as in-AIL-undestaged.

### REFUTED this session (with evidence)
- `dir_evict_prior_tenure=1`: SHUTDOWN cascade (r20 loss → r21-24 got=0). The read-path epoch_stale is the cause.
- `dir_tenure_evict=1 + dir_release_fua_write=1`: WORSE (r7 loss, r8=663, r9=0 cascade). FUA-write at release perturbs/cascades.
- `b_tenure_id` reuse for dir blocks (earlier in sess23, build 0EA92470's first attempt): cascade — b_tenure_id is shared with AG-meta(sess123)/bmbt; daddr reuse → AG-meta tenure logic misread. Use b_mxfs_dir_epoch (dir-specific), NOT b_tenure_id.
- `i_mxfs_ex_grant_seq` is 0 for dirs (egseq=0 96% of P68-EVDECIDE) — unusable as dir tenure counter; use i_dlm_dir_valid_epoch / master epoch.

### THE RESIDUAL (next session's narrow target)
A rare single-entry data-block clobber, vector `comm=bash` (the synchronous create RMW, NOT xfsaild), on a block read THIS tenure (b_epoch==master, so the epoch override can't catch it). HYPOTHESIS (GPT §5 + CLAUDE.md "LIO drops FUA" tension): the modify-evict's re-read clears `_XBF_FUA_FRESH` → forces a SCSI FUA READ that pierces to the PLATTER, but the peer's release-write may still be only in the LIO write-back target cache (not yet on platter) → FUA read returns STALE platter image → RMW clobbers the peer's entry = grant-before-durable.
NEXT to try: (a) in the evict re-read, clear XBF_DONE but NOT _XBF_FUA_FRESH so the re-read is a NORMAL read hitting the COHERENT shared LIO target cache (test if FUA-read-stale-platter is the residual); (b) enforce release→grant ordering so the peer's write reaches the platter before our grant; (c) test fua_disable/fua_always param combos with dir_tenure_evict=1. Then validate full 8/tcp suite + 1/2/4 tcp with dir_tenure_evict default-ON.

See [[sess23-gpt5.5-grant-generation-coherency-design]] [[sess23-tenure-evict-progress-and-gpt-grant-gen-design]].
