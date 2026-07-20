---
name: sess38-GPT-architectural-fix-inail-survives-handoff-release-retire-genbump
description: sess38 GPT-5.5 architectural verdict: dir_reuse loss = writeback authority outlives DLM lock. Fix=release-side retire ALL in_ail dir BLIs + DLM-autho…
metadata:
  type: project
---

## sess38 — GPT-5.5 consult (RULE 5, justified: complete instrumented diagnosis + write-suppress refuted). The architectural verdict on the 8/tcp dir_reuse readdir=799 loss.

### ROOT (GPT, matches my measurement): **MXFS treats the XFS AIL as if the node still owns the metadata after the DLM lock is dropped.** In single-node XFS the AIL may write any committed buffer (one coherent writer). In a shared-disk cluster, once dir EX is released, the node must have NO mechanism left to write that dir's blocks. The measured clobber (`daddr=120 buf_cnt=167 disk_cnt=168 bgen==dirgen(8) stale=0 in_ail=1 dirty=0 in_txn=0 comm=xfsaild`, strict subset of disk) IS a ZOMBIE in_ail buffer from a prior EX tenure that xfsaild reflushes over a peer's durable add. Writeback authority outlived the lock.

### THE INVARIANT MXFS VIOLATES (the strengthened Invariant 1): "flush dirty buffers before releasing EX" is INSUFFICIENT — the bad buffer is dirty=0 but still an AIL checkpoint item, so xfsaild still believes it may write it. Correct rule: **before EX→PR/NL demotion, the dir resource must have ZERO in_ail / dirty / pinned / delwri / under-writeback buffers. Drain AND RETIRE all AIL buffer log items, not just dirty buffers.**

### THE TWO REQUIRED FIXES (both needed):
1. **Release-side (primary — stops the stale background write):** on EX release, while STILL holding EX: freeze new dir txns → force log/CIL + unpin → synchronously WRITE every resource BLI (force-COMPLETE, normal iodone retires the BLI) → wait IO → assert no in_ail/delwri/dirty/flushing/pinned dir buffer remains → mark remaining clean cached buffers stale → publish DLM seq → THEN unlock. NEVER skip-write+emulate-ioend (refuted, my sess38 dir_subset_guard=1 → shutdown). NEVER ail_delete an uncheckpointed item. Retire-without-write (xfs_buf_item_done) is safe ONLY with proof of checkpoint = DESTAGED (mxfs_dir_buf_is_undestaged==false, lseq==wseq).
2. **Gen-bump (secondary — stops next-tenure stale read/modify):** the freshness token must come from the DLM lock's grant/LVB sequence, NOT a local epoch or disk compare. Bump i_dlm_dir_gen on EVERY EX (re)acquire that follows ANY peer EX (Policy A, conservative — over-invalidate is fine), driven by DLM grant-seq/LVB. Acquire-side disk-compare (mxfs_dirrefresh) is REFUTED-racy (peer write not yet on LUN at evict). Write-side suppression is REFUTED-corrupting.

### WHY IT STILL FAILS in current code (my analysis): the release path mxfs_dlm_bast_process→mxfs_dir_flush_data_blocks (xfs_mxfs_dlm.c:7992) DOES flush+retire in_ail dir blocks, BUT it is best-effort: mxfs_dir_flush_one_daddr BAILS on lock contention (P-FLUSH-LOCKWAIT-BAIL) and skips uncached blocks → a contended block's zombie BLI survives. Also the EDEADLK self-demote path (i_dlm_self_demote, ~13976) "may skip the durability drain on a clean read-only drop" — a clean(dirty=0) in_ail buffer is exactly the zombie and may be skipped. Slow-path EX re-acquire DOES bump i_dlm_dir_gen (14117), but a buffer the read hook PRESERVES (in_ail keep-guard, xfs_da_btree.c ~3403-3416) or re-stamps can read bgen==dirgen; and a pure zombie that N never re-reads is flushed by xfsaild with no re-acquire to bump gen.

### EXISTING LEVERS that map to GPT's design (all default-off, to A/B): `dir_zombie_retire` (retire destaged in_ail BLI at release-drain[!DONE only — GAP: doesn't cover DONE destaged] + acquire-evict), `dir_relinval_clean` (xfs_buf_stale clean DONE blocks at release), `dir_tenure_evict` (read+evict master-epoch invalidation that fires even when bgen==dirgen — closest to Policy A but READ-side only, won't stop a pure xfsaild zombie flush). `dir_gen_per_handoff=1` already on.

### NEXT (RULE 4): the precise targeted fix = extend the release retire to **DONE destaged in_ail dir DATA/LEAF buffers** (the !DONE-only gate at xfs_mxfs_dlm.c:1683 + 4090 misses the measured DONE zombie), and make release flush NOT skip on self-demote. Test ALONE. Full GPT design (per-resource BLI list, release state machine, LVB gen) saved verbatim if larger rewrite needed. See [[sess38-DECISIVE-clobber-is-inail-clean-nonstale-subset-genblind]].
</body>
