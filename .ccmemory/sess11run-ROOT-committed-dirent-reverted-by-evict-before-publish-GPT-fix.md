---
name: sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix
description: sess11(ccloop) ROOT for 4/tcp dir_reuse durable loss + GPT-5.5 fix: committed dir dirent's in-core block is XBF_DONE-cleared by evict/cold-read befor…
metadata:
  type: project
---

## sess11 (ccloop 4cb2d0a2) — ROOT of 4/tcp dir_reuse durable single-dirent loss + GPT-5.5 architectural fix

### FIX3 (sess10 build 9527F28F) REFUTED conclusively
P67-POSTREAD-REREAD branch is gated behind `mxfs_dir_postread_reread` which DEFAULTS 0 (reverted sess67: "loss is not gen-stale read"). With flag ON (`dir_postread_reread=1`) it FIRES but REGRESSES to 14/400 (drops own committed work) — same class as sess61. The b_mxfs_grant_gen field is harmless/inert at default; FIX3 does nothing. Read-side gen-stale is the WRONG layer.

### PROVEN ROOT (instrumented, RULE 4) — durable DATA-block dirent loss, NOT a leaf hole
- Symptom: ~80% of 4-node rounds lose ONE `.md5` sidecar (2nd creation wave), e.g. node3_f45.md5 / node4_f22.md5 / node2_f13.md5. LOOKUP_ENOENT + cold-readdir MISS on ALL nodes incl creator = gone from the DATA block on disk (sess21 leaf-rebuild can't fix; readdir enumerates data blocks). Always during the dir's 2→3 data-block GROWTH/rebalance window (size 8192→12288, fmt=2 EXTENTS, LEAF1).
- Creator commits the dirent (P-CRNAME-DONE rval=0). Publish-on-create `mxfs_dlm_dir_durable_signal` runs xfs_log_force(SYNC)+`mxfs_dir_flush_data_blocks` ~240us later.
- DECISIVE: the lost name appears in ZERO P-RELFLUSH and ZERO P11-FLUSH-CLEANSKIP name-lists on ALL 4 nodes the whole round (vs the DATA file node2_f13 in 17-59). So its in-core dir block NEVER contained it at ANY flush/skip — the committed entry was REVERTED out of its in-core buffer before any flush captured it. At the create-flush, off1(daddr39771328) flushed with only DATA-file names (none of node2's just-committed .md5), proving the buffer image reverted to the stale data-files-only disk image.
- P11-FLUSH-UNCACHED added this session = NOT the uncached-skip path (mostly 0 for the lost block). P-DIRWR logs crc+count, NOT names (so "absent from P-DIRWR" was a false signal earlier).

### Mechanism (GPT-5.5 RULE-5 consult, high confidence)
A CONCURRENT thread (peer BAST, fast speculative EX grant/release churn — saw EXGRANT→P62-RELOAD→P106-MR-EVICT→EXREL drain_ms=0 right before the create — or the grow/rebalance read path) runs `mxfs_dir_evict_data_blocks` between the addname commit and the publish flush. After log_force(SYNC) the buffer can look "clean" (not dirty/pinned, maybe not in_ail) so the evict heuristic `dirty||pinned||delwri||!DONE||(in_ail&&!incarn_aba&&undestaged)` FALSELY clears XBF_DONE; then a normal dir read cold-refills the SAME xfs_buf from the stale home block (entry not yet destaged). log_force(SYNC) itself doesn't revert memory — it just enables the false-clean transition. XFS buffer flags are NOT a valid proxy for "home block contains this committed dirent" — peers cold-read the device, so LOG durability ≠ HOME-block durability.

### GPT-5.5 FIX (architectural) — per-EX-grant TOUCHED-BUFFER writeback fence (= option ii + (i) scoped to touched bufs)
1. Mark every dir DATA buffer modified under the current EX grant `b_mxfs_cluster_undestaged=true` (+xfs_buf_hold), recorded at the low-level dir-data log points (xfs_dir2_data_log_entry/header/unused, xfs_da_log_buf) — NOT rediscovered by later extent scan.
2. `mxfs_dir_evict_data_blocks` (and any cold-read/reload) MUST refuse to clear XBF_DONE on a `cluster_undestaged` buffer, REGARDLESS of XFS dirty/pinned/AIL state.
3. Publish: after commit+log_force(SYNC), for each touched buffer synchronously write it HOME even if it looks clean, THEN clear the flag. Only then DLM unlock/downgrade. (Don't CLEANSKIP a touched buffer.)
4. BAST must NOT evict/reload a dir with an active local unpublished publisher — mark refresh_deferred + wait for publish (BAST only schedules; owner/worker publishes in normal lock order = deadlock-safe).
5. Avoid over-fire regressions: tie clean-block refresh to a PEER durable epoch (LVB), not local grant churn. NEVER invalidate a locally cluster-undestaged buffer.
6. Do NOT union-merge dir DATA blocks (variable-size entries/bestfree/tail/crc — corrupts allocator). EX serialization + write touched home blocks before release is the correctness foundation.
Assertions: BUG_ON(clear_XBF_DONE/cold_read(bp) && bp->b_mxfs_cluster_undestaged); BUG_ON(dir_has_undestaged_bufs(dp)) before DLM unlock.

### State: tree = build 1D3115A5 (baseline DE3A7E21 + FIX3 inert + P11-FLUSH-UNCACHED/CLEANSKIP probes). Cluster test1-4 grub now has log_buf_len=16M (16M ring survives the storm). Repro: `bash tests/tcp/drc4_capture.sh 24` (cold-reset+prep dirwr=2+drc4_repro). Validate: `bash tests/tcp/validate_drc4.sh N`.
### NEXT: implement the scoped touched-buffer fence (steps 1-3 minimal). See existing mxfs_dir_buf_is_undestaged machinery to build on. [[sess10run-GPT-consult-durable-clobber-stale-inAIL-block-survives-release]] [[sess61-grant-gen-fix-REFUTED-overfires-need-peer-owner-signal]] [[sess21-leaf-rebuild-fix-works-90of91-residual-stale-datablock]]
