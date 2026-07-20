---
name: sess47-FIX-release-flush-undestaged-DONE-dir-block
description: sess47 FIX (build 7ED27741, KEEP): release drain (data_durable + flush_data_blocks) now also lands XBF_DONE-but-logged-never-written (lseq!=wseq) dir…
metadata:
  type: project
---

## sess47 (ccloop 8ddb16a2) — undestaged-DONE release flush FIX (KEEP)

### Build: 7ED2774139804E86CFD331F (from EF006296 baseline). Also carries a P47-NLSKIP-UNDEST always-on probe (confirmed 0× — NL-skip is NOT the wseq=0 producer; can remove).

### THE FIX (xfs/xfs_mxfs_dlm.c, two matching edits):
`mxfs_dir_data_durable` (`bad` ~L1069) and `mxfs_dir_flush_data_blocks` (`needs_flush` ~L1249) used `dirty||in_ail||pinned||delwri` and MISSED a dir block that is **XBF_DONE + clean (!dirty !in_ail !pin !delwri) yet LOGGED-NEVER-WRITTEN (b_mxfs_logged_seq != b_mxfs_written_seq)**. Added `|| ((dbp->b_flags & XBF_DONE) && mxfs_dir_buf_is_undestaged(dbp))`. Gated on XBF_DONE so an evict-invalidated stale image (!DONE, sess33) is never re-written. Safe at release (holder owns EX, block authoritative). Converges: xfs_bwrite snapshots wseq=lseq.

### EVIDENCE / IMPACT (clean reboot full `./run.sh 2 tcp`):
- baseline EF006296: 15/17, FAIL cache_coherency(uv) + crash_consistency.
- 7ED27741: 15/17, FAIL cache_coherency(uv) + tcp_dlm_scaling. **crash_consistency + dir_reuse now PASS.** Net positive for the dir family.
- cache_coherency(uv) standalone: 0/2 (baseline) → 1/3 (fix). Improved but STILL flaky.

### uv ROOT (PROVEN, always-on DIR-STALE-SKIP, instrumentation HIDES it — dirwr=1 makes uv PASS):
`DIR-STALE-SKIP ino=<uvdir> blk=0 buf_gen=2 inode_gen=3 pin=1 dirty=0 in_ail=0 li_empty=1 lseq=250 wseq=0 undest=1`. test1's block 0 is STALE (peer's deletes via EVICT-RING-DIRMOD bumped inode_gen, fired 9×; P-TCPEX-REACQ=0/P108=0 so NOT phantom-EX), PINNED (read hook xfs_da_btree.c:3228 `!xfs_buf_ispinned` guard → DIR-STALE-SKIP serves stale), and UNDESTAGED (wseq=0 = never written to platter). The read hook (3216) WOULD invalidate+cold-read but the PIN blocks it; even unpinned, undestaged → cold-read would lose test1's own deletes unless platter has the superset. **Merge dilemma: block 0 = {test1 deletes applied, node2 deletes missing} in-core only; platter = {node2 deletes, maybe missing test1's}. Neither is a superset.** Fundamental under LAZY lock caching (sess34 6s lazy release) + async EVICT-RING gen propagation: a node accumulates undestaged mods on a base that goes stale async, and modify_refresh/consumer_refresh use the NON-draining evict that SKIPS pinned blocks.

### NEXT (untried this session): (A) make drain_evict (mxfs_dir_drain_evict_data_blocks ~L3531) log_force(SYNC) UNCONDITIONALLY (not gated on the trylock any_pinned scan that misses a LOCKED block) so a prior-tenure pin reliably clears at re-acquire. (B) strict-serialization-on-contention: when a dir is contended (BAST/evict-ring), release promptly (no lazy EX cache) so the platter stays the serialization point. (C) carry dir_gen in the DLM grant (LVB) to kill async-gen lag. durable_signal per-modify destage is OUT (v0.5.1: 60s on 8.7k rsync, RULE 0). [[sess46-UNIFIED-ROOT-pinned-shared-dir-block-merge-dilemma]]

### SEPARATE blocker: tcp_dlm_scaling = `xfs_iunlink_item_precommit` Metadata corruption (0x8) → `__xfs_trans_commit:890` shutdown ~round N. AGI unlinked-inode-list cross-node coherency (NOT dir blocks). Pre-existing (sess45). Flaky.
