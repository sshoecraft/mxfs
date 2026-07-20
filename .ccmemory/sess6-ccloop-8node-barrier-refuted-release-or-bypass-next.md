---
name: sess6-ccloop-8node-barrier-refuted-release-or-bypass-next
description: sess6(run6614): GPT must-complete-barrier (log_force+retry drain_evict until left==0 on handoff) REFUTED at N=8 (1/5, no help) — residual 1-3 dirent…
metadata:
  type: project
---

## sess6 (run 6614) — N=8 dir_reuse: barrier refuted; refined hypothesis

### SHIPPABLE BUILD: back to **9AA569A0** (gg_refresh=1 + leaf_flush=1; barrier reverted — srcversion identical). 1/2/4 tcp=100%, 8/tcp=16/17, N=8 dir_reuse ~1/3-1/5.

### REFUTED this session (do NOT retry): GPT-5.5's "must-complete invalidation barrier" — in the gg_refresh handoff path, loop `log_force(SYNC)+msleep+drain_evict` until left==0 (wait out pin/undestaged skips). Built (414432A9), tested N=8: **1 PASS / 4 FAIL of 5, same rate, smaller latency budget wasted**. Reverted.
- DECISIVE IMPLICATION: the residual 1-3 dirent loss SURVIVES a fully-evicted cold-read base (left==0). So it is **NOT the acquire-side pin/undestaged skip** (GPT's primary theory) — evicting everything and cold-reading still misses the dirent. The peer's dirent is EITHER not durable on the LUN at cold-read time (release-side gap) OR the clobbering node never ran gg_refresh at all.

### REFINED HYPOTHESES for N=8 dir_reuse fine tail (1-3 scattered dirents, late high-node .md5 creates, durable, all nodes agree):
1. **gg_refresh BYPASS acquire path**: gg_refresh lives ONLY in the dir-EX cached fast-path serve `else` block (~14533+). Other serve paths skip it: the DEMOTER-BYPASS (i_dlm_demoter==current, ~15106 — "acquires WITHOUT reload", P68-INSTR showed ~30% of dir ilock entries take a bypass on the failing node in older sessions), and possibly the mode==EX fast path admitted before the refresh. A node serving a dir-EX via bypass RMWs a stale base → drops a peer's dirent. CHECK: does the clobbering acquire go through gg_refresh or a bypass? Instrument (lightweight atomic counters, like the P6 phantom counters that worked) which serve-path the dir-EX ops take at N=8.
2. **release-durability gap**: durable_signal (mxfs_dir_flush_data_blocks→flush_one_daddr uses SYNCHRONOUS xfs_bwrite + blkdev_issue_flush, so a flushed block IS durable) — BUT it's gated `i_dlm_dir_gen>0 && fmt EXTENTS/BTREE`. A block missed if gen==0 (fresh dir round1) or if the peer's LAST addname committed but durable_signal ran before that commit landed the block in-core. CHECK: is durable_signal called + flushing the specific lost block for the peer's late create?

### NEXT (RULE 4): add lightweight atomic counters (no printk) for (a) dir-EX serve-path taken (gg_refresh vs demoter-bypass vs mode-fast) and (b) at each dir data-block modify, whether i_dlm_dir_gen changed since loaded (stale base). Run N=8, correlate counters with a fail. Target whichever path serves the stale RMW. The P6-DIRPHANTOM counter pattern (atomic64 + dirphantom_dump-style param) is the proven no-heisenbug approach.
See [[sess6-ccloop-8node-dirreuse-undercount-refuted-levers]] [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]]</body>
