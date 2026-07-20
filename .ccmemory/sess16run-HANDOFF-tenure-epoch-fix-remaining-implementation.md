---
name: sess16run-HANDOFF-tenure-epoch-fix-remaining-implementation
description: sess16(ccloop) HANDOFF: tenure-epoch dir-coherency fix — plumbing DONE in tree (build 8524552B, all gated OFF). Remaining: (a) stamp b_mxfs_dir_epoch…
metadata:
  type: project
---

## sess16 (ccloop) HANDOFF — tenure-epoch fix: what's done, what remains

### DONE this session (in tree, build 8524552B, ALL gated OFF = safe baseline == 48C6A95E)
- `b_mxfs_dir_epoch` field (xfs_buf.h) = the coherent-tenure stamp.
- Stamp on fresh disk read + postread-reread (xfs_da_btree.c).
- **Stamp on dir-block CREATE**: xfs_dir3_data_init (xfs_dir2_data.c) + xfs_dir3_leaf_init (xfs_dir2_leaf.c) → `bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch`.
- PRIOR-TENURE evict override (mxfs_dir_evict_data_blocks, param `dir_evict_prior_tenure` default 0): force-evict a kept block whose `epoch!=0 && epoch < valid_epoch`.
- MX-DOUBLEGRANT auditor (dlm/dlm.c, KEEP, always-on logging).

### The REMAINING gap (why it's not done) and the fix
P16-PRIORTENURE fired only 10-20× (vs 6000 evicts): block0 is CREATED at tenure 0 (valid_epoch==0 then) → stamped epoch 0 → the `epoch!=0` guard SKIPS it forever even after valid_epoch climbs. To catch it, DROP the `epoch!=0` guard so `0 < valid_epoch` counts as stale. BUT that resurrects a block created at tenure 0 then MODIFIED in the current tenure with committed-unwritten work (epoch still 0 because stamp only fires on create/fresh-read, not modify) → flagged stale → evicted → loses our current work.

### So the REQUIRED remaining steps (next session)
1. **Stamp on MODIFY**: wherever a dir DATA/LEAF block is logged this tenure (xfs_dir2_data_log_*, xfs_dir2_leaf_log_*, or centrally in xfs_da_buf logging / xfs_trans_log_buf for dir blocks), set `bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch`. Now ANY block we touched this tenure carries the current epoch; only a genuinely-untouched-since-prior-tenure block (incl block0 served as cache-hit) lags.
2. **Drop the `epoch != 0` guard** in the prior-tenure override (xfs_mxfs_dlm.c, my P16 block) — change `dbp->b_mxfs_dir_epoch != 0 && ... < valid` to just `valid_epoch != 0 && dbp->b_mxfs_dir_epoch < valid_epoch`. Resurrection now prevented by step 1 (our current work carries current epoch) + the dirty/pin/delwri/!DONE hard guards.
3. Enable `dir_evict_prior_tenure=1`. Verify i_dlm_dir_valid_epoch advances reliably BEFORE the modify-evict (it does via P65-EPOCH-ADOPT, dir_epoch_adopt=1).
4. Consider also stamping xfs_dir3_free_init (freeindex) for completeness.

### VALIDATE
mht=50 dirwr=0: P16-PRIORTENURE should fire MANY times (covering block0); P-DIRWR daddr=120 count MONOTONIC; dir_reuse 8/tcp PASS across ≥5 clean-reboot runs (FLAKY race — dirwr/instr MASK it, so validate at dirwr=0/instr=0 only). Then mht=50 tcp_dlm_scaling ≤60s, full 8/tcp 17/17, then 1/2/4. CANARIES (resurrection): unlink_visibility, rename_visibility, crash_consistency must stay PASS. RULE-0: watch timing from extra re-reads.

### If it STILL fails after steps 1-3
Fall back to GPT release-side REVOKING-fence (parts 1+2) [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]]. Key proven facts to keep: double-grant RULED OUT [[sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer]]; acquire-side disk-compare refresh is racy [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]]; no mht reliably passes [[sess16run-CORRECTION-dirreuse-fails-at-mht300-too-no-reliable-mht]]; loss survives force_coherent/postread/release_invalidate/release_fua. Criterion NOT met — marker not written.</body>
