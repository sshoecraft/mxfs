---
name: sess124-mht-fixes-starvation-real-root-is-inail-acquire-fence
description: sess124 (ccloop): MHT batching (build 4F692D9C) FIXED the inode-EX starvation (123s→fast, no shutdown) — KEEP. But cache_coherency still FAILs: prove…
metadata:
  type: project
---

## sess124 — MHT fixes starvation; remaining root = in_ail prior-tenure AG-meta acquire-fence gap

### MHT (Minimum Hold Time) batching — KEEP (build 4F692D9C5E3DA9A092B9319)
Implements Gemini RULE-5 fairness design #3 (see [[sess123-caw-ex-starvation-gemini-fairness-design]]). Fresh inode-EX grant stamps `i_dlm_ex_acquire_ns`; a peer BAST within `mxfs_inode_mht_ms` (default 50ms, param `inode_mht_ms`) is DEFERRED (keep state CACHED, arm `i_dlm_bast_dwork` delayed_work for the window remainder) so the holder batches its queued ops in one tenure. 6 edits: `xfs_inode.h` (+`i_dlm_bast_dwork`,`i_dlm_bast_pending`,`i_dlm_ex_acquire_ns`); `xfs_mxfs_dlm.c` (param decl ~1182; `mxfs_dlm_bast_dwork_fn` + `mxfs_dlm_mht_defer_bast` after bast_work_fn; MHT call in bast_notify before holders-split; stamp at the 3 EX-upgrade sites + grant_local_new; INIT_DELAYED_WORK + cancel_delayed_work_sync).
RESULT (RULE 4 proven): unlink_30_files went 123174ms(max)→116–2465ms, **zero shutdowns** on all 4 nodes. Starvation/ETIMEDOUT-shutdown ELIMINATED. KEEP.

### MHT is NOT the cache_coherency regression (control proven)
unlink_visibility still FAILs. Ran `inode_mht_ms=0` (functionally == prior build FA1D1C0D): STILL fails content — node1 `All 120 files exist: actual=96` (24 dirents lost), node2 `Failed to delete node2_file1..4`, slow (starvation back). With mht=50: actual=30, faster. So the dirent lost-update is INDEPENDENT of MHT; MHT only changes timing/severity. (Prior session's "content 100% correct" claim was over-optimistic / measured a run that shut down before the create-visibility compare.)

### PROVEN ROOT (RULE 4): in_ail prior-tenure AG-meta + dir-block lost-update
dmesg all 4 nodes: **P124-ALLOC-REVERT** ×16 (xfsaild writes a STALE prior-tenure bnobt/cntbt buffer over the COHERENT on-disk image, reverting a peer's durable alloc); **P125=0** (node LEGITIMATELY holds the AG when it does this — not a mutual-exclusion bug); **P-DIRWR clobber** ×90-126 (dir-block write resurrects deleted/higher-count dirents = dirent lost-update). Both free-space and dirent faces share one root: a node holding AG/dir EX writes back a stale prior-tenure cached buffer.

The stale buffer signature: `in_ail && !dirty && !pin && !delwri && !undestaged` — committed by THIS node in a PRIOR tenure (we released+re-acquired the AG since), but a peer modified the block on disk in between.

### THE GAP (sess123 tenure_id fix is partial)
`xfs_btree_read_buf_block` (xfs/libxfs/xfs_btree.c:1433) stamps `b_tenure_id = pag->ag_dlm_tenure_id` on EVERY successful read INCLUDING CACHE HITS (xfs_trans_read_buf returns cached XBF_DONE buf w/o I/O). So a prior-tenure in_ail buffer that survives `mxfs_ag_meta_invalidate_stale` (it CAN'T be discarded — clearing XBF_DONE on a committed/in_ail buf → "Corruption of in-memory data" shutdown, sess22/sess118) gets RE-STAMPED to the current tenure → tenure guard (xfs_mxfs_dlm.c:5487) then treats it as this-node-authoritative forever → xfsaild writes it → reverts peer. tenure_id reflects "when last READ", not "when last MODIFIED/committed".

### Prior failed approaches (do NOT repeat)
- Write-side suppression/refresh of the stale bnobt at submit (P122/P124 in pal/linux/xfs_buf.c): regressed cache_coherency to 0/4 + "Corruption of in-memory data" shutdown — refreshing ONE bnobt desyncs sibling cntbt/AGF in-core (sess22/sess118). P124 is LOG-ONLY by design.
- Read-side gen invalidate (b_mxfs_ag_gen vs pag_dlm_meta_gen): partial.
- sess123 tenure read-side guard: partial (the cache-hit re-stamp gap above).

### NEXT (RULE 5 — consulting Gemini): the fence must be at AG ACQUIRE / RELEASE
Core question: guarantee that after an AG BAST release there are NO in_ail prior-tenure AG-meta buffers lingering (drain pipeline must writeback+AIL-remove bnobt/cntbt/inobt/AGF before on-disk unlock — Invariant #1), so re-acquire sees only clean (safe to cold-read) or current-tenure-modified (keep) buffers. OR stamp tenure on MODIFY not READ. Same for dir DATA blocks. Avoid discarding in_ail bufs (log corruption) and avoid per-buffer write-side refresh (sibling desync).

Related: [[sess123-tenure-id-FIXED-agi-corruption-now-starvation]] [[sess123-caw-ex-starvation-gemini-fairness-design]] [[sess23-ccloop-suppression-was-corruptor-3of4]] [[feedback_timing_is_first_class]]
