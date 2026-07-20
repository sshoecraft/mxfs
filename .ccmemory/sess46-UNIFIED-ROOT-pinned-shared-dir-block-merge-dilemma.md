---
name: sess46-UNIFIED-ROOT-pinned-shared-dir-block-merge-dilemma
description: sess46 UNIFIED ROOT of the whole 2/tcp dir-coherency flaky family (uv/dir_reuse/crash_consistency): a node's concurrent same-dir mods PIN the shared…
metadata:
  type: project
---

## sess46 — THE UNIFIED ROOT of the 2/tcp dir-coherency flaky family (FRESH evidence, saved to /src/mxfs/tests/_cap/)

### One root explains uv + dir_reuse + crash_consistency (all flaky, all dir-block read staleness):
When two nodes concurrently modify the SAME shared dir, each node's own committed-but-not-checkpointed mods **PIN** the shared dir block (in the CIL: `pin=1 has_bli=1 li_empty=1 undest=1 in_ail=0`, gen-stale `buf_gen=0 < inode_gen`). The read-path coherency hook (xfs_da_btree.c:3216-3229) then hits `DIR-STALE-SKIP` (line 3261) and SERVES THE STALE block → the node misses the peer's concurrent mods:
- **uv** (cache_coherency): node1's data block pinned by node1's OWN deletes of node1_file* → still lists node2_file21..30 (node2's deletes invisible). `uv none remain got=10`.
- **dir_reuse**: node1's LEAF block (blk=0x800000) pinned → missing node2's last ~15 hash entries → lookup_fail.
- **crash_consistency**: same, small-file .md5.

### WHY EVERY DIRECT FIX IS PROVEN-HAZARDOUS (do NOT repeat — all tried/refuted):
1. **Refresh the pinned block** (clear XBF_DONE + re-read): the `!xfs_buf_ispinned` guard at xfs_da_btree.c:3228 blocks it BECAUSE **sess64 PROVED** relaxing it races writeback/unpin → `xfs_inode_buf_verify` corruption → FS SHUTDOWN (build C7BF9BFD). The pin guard MUST stay.
2. **Destage the pinned block** (force AIL/CIL push to disk): writes node1's version which STILL shows node2_file21..30 → resurrects node2's deleted files → CLOBBERS node2's deletes (P-LEAFWRITE CLOBBER confirmed write-side).
3. **Drop the pinned block** (xfs_buf_stale + abort in-AIL BLI): unsafe (sess26 GPT) → log/AIL corruption.
4. **Drain-then-evict on the READ path** (log force + wait-unpin like the acquire-side mxfs_dir_drain_evict_data_blocks does): RULE-0 perf — sess97 proved a per-op drain = 5.5x unlink slowdown (28s→155s), reverted.
5. **force_block=1**: regresses dlm_fairness/cache_coherency (sess44). flag-flip forbidden.

### THE ACTUAL DILEMMA: node1's pinned in-core block = (node1's mods applied) + (node2's mods NOT applied). node2's LUN block = (node2's mods) + (node1's mods IF node2 read node1's block first). Neither in-core nor a naive disk re-read is a guaranteed superset. The block is a single unit; two nodes' concurrent RMWs from divergent bases can't both survive a block overwrite.

### THE ONLY ARCHITECTURALLY-CORRECT DIRECTIONS (next session — these are MAJOR, pick one + commit):
(A) **Strict serialization / prompt checkpoint**: ensure a node's dir block is UN-pinned (CIL-checkpointed to disk) before it RELEASES EX, AND the peer re-reads only AFTER. The test's `sync` SHOULD unpin node1's block but the evidence shows pin=1 at the post-barrier read → node1's CIL checkpoint is LAGGING (or the block is re-pinned). ROOT-CAUSE why `sync`/release leaves the dir block pinned (instrument the CIL push / xfs_log_force vs the dir block's pin lifecycle at release). If release reliably checkpoints+destages the dir block (unpinned, on disk) before EX handoff, the peer's next acquire cold-reads a coherent superset and the pinned-stale case never arises. This is sess43's "dir writes platter-durable" conclusion — but must avoid the per-op perf hit (only force at RELEASE/handoff, not per-op).
(B) **Block-level MERGE**: when a node would RMW a stale-but-pinned shared dir block, merge the peer's committed entries (from a FUA disk read) into the in-core block before/after the local mod. Complex; leaf hashvals are sorted, addresses point into data blocks.

### STATUS: build EF006296 unchanged (0 edits). Suite flaky 13-16/17, never 17/17 ([[sess46-CRITICAL-suite-is-broadly-flaky-never-17of17-clean]]). Also a SEPARATE flaky root: fence_during_write (fence latency, cascades). Evidence: /src/mxfs/tests/_cap/cc_fail_t1_*.log. [[sess46-PROVEN-dir_reuse-leaf-hole-is-async-evictring-lag-stale-leaf-RMW]] [[sess46-dir_reuse-fix-vectors-and-hazards-map]]</body>
