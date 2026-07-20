---
name: sess23-residual-block-bypasses-evict-needs-ownedex-read-coverage
description: sess23(ccloop) DECISIVE: the dir_tenure_evict residual clobber block (r7 node3_f20.md5 @ daddr=100474824) gets NO P23/P68 evict decision on ANY node…
metadata:
  type: project
---

## sess23 (ccloop) DECISIVE — the residual clobber block bypasses the evict

Reproduced residual with `dir_tenure_evict=1 dirwr=1`: r7 lost `node3_f20.md5` (all 8 nodes agree, durable). Traced its block:
- node3_f20.md5 lives in **daddr=100474824** (consistent across test1/2/3).
- P35E-DIRWR writers of that daddr at r7: **node3 (comm=bash, many writes** — adding its md5 entries), **node2 (comm=bash, once)**, node1 (comm=rm, the legit rm-rf decreasing nent 8→1).
- **NO P23-TENURE-EVICT and NO P68-EVDECIDE for daddr=100474824 on ANY node.**

### Interpretation
P68-EVDECIDE fires inside mxfs_dir_evict_data_blocks' per-block loop ONLY for blocks found CACHED (xfs_buf_incore==0). Its total absence for the clobbered daddr means the modify-evict NEVER processed this block — either it was uncached at evict time ("not cached => next read fetches", continue, no P68) or the node's extent walk didn't reach it. **So the evict-side fix (P23-TENURE-EVICT / master-epoch sync) structurally CANNOT catch this residual** — the stale base never goes through the evict.

If the block was uncached at the clobberer's evict, then its addname READ fetched it. That read, under owned_ex, takes the `!owned_ex`-gated SKIP in xfs_da_read_buf (lines 3154/3176) → NO read-time coherency invalidation → if the fetched/cached image is stale, it's served as the RMW base. A fresh uncached read should FUA-fetch current (LIO coherent)… so the residual is likely an owned_ex CACHE-HIT on a stale XBF_DONE buffer that the evict didn't visit (cached AFTER the evict ran, e.g. by an EEXIST lookup or readdir earlier in the same op, or re-cached between evict and addname).

### NEXT SESSION — fix direction shifted to the READ path
The fix must cover the **owned_ex dir-DATA read** in xfs_da_read_buf (currently entirely skipped for EX owners). Options:
1. Extend the read-time coherency check to ALSO run under owned_ex for dir DATA blocks when `b_mxfs_dir_epoch < master_epoch` (mxfs_v5_dlm_inode_dir_epoch) — force XBF_DONE clear + FUA re-read of a stale cached base even on the RMW read, not just at the op-start evict. Use the SAME master-epoch sync that worked for the evict (sess23 breakthrough). MUST keep the dirty/pin/delwri/in-AIL-undestaged-CURRENT guards to avoid resurrection (a current-tenure block has b_epoch==master → not touched).
2. OR make mxfs_dir_evict_data_blocks also handle the uncached case by stamping so the subsequent read is forced FUA.

Verify with the generalized content-subset read probe (see [[sess23-fua-disable-refuted-residual-needs-generalized-probe]]) that the owned_ex base read is a stale cache-hit.

Base build B17FED9A (dir_tenure_evict default-off). Best result so far: flaky PASS, no cascade. See [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]] [[sess23-residual-is-single-holder-not-doublegrant]].
