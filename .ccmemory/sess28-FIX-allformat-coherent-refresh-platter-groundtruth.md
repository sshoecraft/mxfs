---
name: sess28-FIX-allformat-coherent-refresh-platter-groundtruth
description: sess28(ccloop) THE FIX (build 9AB8E8AE, default-on): mxfs_dir_addname_coherent_refresh — dedup'd FUA platter check + SAFE brelse+verified-reread of C…
metadata:
  type: project
---

## sess28 — THE FIX for dir_reuse 8/tcp read-side staleness (build 9AB8E8AE)

### Root (PROVEN, [[sess28-PROVEN-readside-staleness-targeted-platter-guard]])
Node holding dir EX serves a CLEAN cached dir DATA block STALE vs the durable platter (lossy TCP gen/epoch leaves it current-stamped: dir_gen==loaded_gen, bufepoch==valid at the clobber). Its bestfree offers a slot a peer durably filled → use_free overwrites the peer's dirent. NO local signal distinguishes the stale block → only the PLATTER is ground truth. Baseline confirmed: coherent=0 → rdmiss=1 clean loss (NO shutdown), ~50% flaky.

### The fix: `mxfs_dir_addname_coherent_refresh(args, dbp)` (xfs/libxfs/xfs_dir2_data.c, param dir_addname_coherent DEFAULT 1)
Called after `bf = bestfree_p(...)`, before dup/use_free, in ALL THREE addname formats: node (xfs_dir2_node_addname_int), leaf (xfs_dir2_leaf_addname, grown==0), block (xfs_dir2_block_addname). Logic:
1. Gates: multinode, published dir, CLEAN buffer only (XBF_DONE && !dirty && !in_ail && !pinned && !delwri).
2. **RULE-0 DEDUP (critical)**: skip if `b_mxfs_coherent_gen == dir_gen` (already verified this tenure). NEW xfs_buf field b_mxfs_coherent_gen (xfs_buf.h ~L240), set ONLY by this helper (unlike lossy b_mxfs_dir_gen stamped on every read). Staleness arises ONLY from a peer modify, which forced our release+reacquire → slow-path gen bump (xfs_mxfs_dlm.c ~L12735); so a gen change is the necessary precondition. Within one gen we hold EX continuously → no new staleness → dedup is sound. Reduces FUA reads from O(addnames)=~6400 to O(blocks×gen-changes) → wall stays ~355s (under 480s budget).
3. FUA-read THIS daddr. If platter is a CURRENT valid block of this dir (magic==XDD3/XDB3 && owner==ino): set coherent_gen=dir_gen; if memcmp(platter, in-core)!=0 → STALE → **clear XBF_DONE|_XBF_FUA_FRESH + b_mxfs_dir_gen=0, return 1** (log P28C-STALE). Caller then xfs_trans_brelse + re-reads via xfs_dir3_data_read/xfs_dir3_block_read (VERIFIED read path) so bestfree reflects the peer's entry.

### CRITICAL: do NOT memcpy the platter in place (sess28 trap)
The first fix version memcpy'd the FUA platter image into dbp->b_addr in place — bypasses the read verifier → injects a block that fails a LATER dir3/CRC check → shut=3000+ SHUTDOWN cascade + wedge (build E40CD553 REFUTED). The SAFE form invalidates (clear XBF_DONE) + lets the standard read path cold-re-fetch WITH verification (node guard=2 proved this safe: PASS 8/8, 0 shutdowns).

### Validation status (build 9AB8E8AE): coherent=1 runs 1-3 PASS, shut=0, wall 352-361s (no wedge), but p28c=0 (those runs had no staleness — bug is ~50% flaky, they were the clean half). p28c=0 means fix≡baseline, so NOT yet proven on an actual staleness event. Running 8-run batch to hit a P28C-STALE event (prove catch) or establish a pass streak. NEED: a run with p28c>0 AND pass (proves the fix catches a real clobber). Working modargs: dir_gen_per_handoff=1 dir_modify_extent_adopt=1. See [[sess28-PROVEN-readside-staleness-targeted-platter-guard]].
