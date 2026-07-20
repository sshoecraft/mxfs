---
name: sess32-FIX-ex-side-epoch-revalidation-build-5BD1CE5F
description: sess32 FIX (build 5BD1CE5F, validating): EX-side prior-tenure dir revalidation. owned_ex gate at xfs_da_btree.c:3190 relaxed when dir_tenure_evict on.
metadata:
  type: project
---

## sess32 — EX-side prior-tenure dir revalidation (GPT RULE-5 design)

### Root (PROVEN, GPT-confirmed)
The dir_reuse single-dirent loss = an EX holder RMW's a CLEAN prior-tenure cached dir DATA block (a stale base missing a peer's durable add) → xfsaild destages it → reverts the peer's dirent (P-WMERGE MERGE-NEEDED, held_mode=EX, in_ail=1, disk_extra=1 incore_extra=1). The read-time staleness machinery (gen/epoch/ABA in xfs_da_read_buf) was **entirely gated `!owned_ex`** (xfs_da_btree.c:3176) — "EX grants authority, not freshness." So under EX nothing revalidated; the stale base was served as a cache hit. GPT-5.5: make DLM EX acquisition a cache-coherency boundary (GFS2 glock model); revalidate cached metadata under EX too; use FUA reads (LIO target: plain bio is per-initiator-stale, FUA is the coherent primitive — xfs_mxfs_dlm.c:17904).

### The fix (build 5BD1CE5F)
xfs/libxfs/xfs_da_btree.c: wrapped the read-time invalidation block; new gate runs it under EX when `mxfs_dir_tenure_evict` is on (multi-node):
`((!owned_ex && dir_gen!=0) || mxfs_ex_reval)` where `mxfs_ex_reval = dir_tenure_evict && m_mxfs_dlm && !single_node`. Inside, the epoch (`tenure_stale`/`epoch_stale`) check is owned_ex-independent; the invalidate clean-guard (!in_ail||!undestaged etc.) + valid_epoch sync (only first read/tenure invalidates) protects our own unpublished work (sess43 hazard avoided).

### PROVEN it now fires under EX (params dir_tenure_evict=1 + dir_evict_prior_tenure=1, dirwr=1)
`P16-PREREAD-EPOCHSTALE ino=131 buf_epoch=131 master_epoch=137 in_ail=0 — invalidate stale prior-tenure read base` — fires on CLEAN prior-tenure blocks under EX. Master epoch advances on handoff (137>131). Previously (without my gate) P16 fired 0× under EX.

### Needs BOTH params (current code): dir_tenure_evict=1 (enables EX gate) + dir_evict_prior_tenure=1 (enables epoch_stale trigger which actually invalidates). dir_tenure_evict alone left WMneeded firing.

### VALIDATING: clean run `drc_repro_loop.sh 6 "dir_tenure_evict=1 dir_evict_prior_tenure=1 dir_writeprobe=1 dirwr=1" 24`. Baseline loses ~1/2; need 6/6 clean + no shutdown. If clean: make both default, full 8/tcp ×3, re-verify 1/2/4. [[sess32-PROVEN-owned-ex-disables-gen-mechanism-wmerge-root]]
</body>
