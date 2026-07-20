---
name: AAA-ccloopa864-sess7-FIX-target-AG-freespace-doublealloc
description: sess7 FIX TARGET: dir_reuse@32/caw root = AG free-space DOUBLE-ALLOC (block used as dir-btree-leaf AND dir-data on coherent medium). dir_force_block=…
metadata:
  type: project
---

## sess7 (ccloop a864) — dir_reuse@32/caw FIX TARGET: AG free-space DOUBLE-ALLOC (the confirmed root)

This session PROVED the 32/caw dir_reuse failure is R-a WRITER/ALLOCATION-side (see sibling memory AAA-ccloopa864-sess7-ROOT-bmbt-XDD3...): rank1 adopts a COHERENT dinode (P133 silent) whose bmbt leaf daddr, on the coherent medium, holds a dir-DATA block (XDD3) — a block DOUBLE-ALLOCATED. This IS the multi-session-known **AG free-space double-alloc** ("Bug B"). Reader-side fixes are exhausted (this run + many prior).

### KEY: dir_force_block=0 is ALREADY the default (confirmed on node) — that + ~30 dir_* coherence params fixed 2/4/8/16 caw (all PASS). 32 is the holdout = the double-alloc still occurs at 32-node concurrency. So the fix is NOT dir_force_block.

### AG-allocation module params exposed (candidates to A/B at 32): **lazy_ag_drain** (PRIME SUSPECT — if AG drain is deferred, a releasing node may not flush bnobt/cntbt free-space before handoff → peer allocates a stale-free block → double-alloc), ag_skip_dblfree, dbg_ialloc_dblcheck, dblalloc_probe, ag_bast_stall_iters, ag_yield_quantum/adaptive, dir_drain_epoch_skip, dir_drain_merge, ifree_drain_ms.

### PRIOR ART TO READ FIRST (do NOT repeat refuted approaches):
- **`caw-4node-doublealloc-current-code-state-and-next-probe`** (age ~4d, THIS run — CURRENT code state + next probe; says "release-side bnobt/cntbt hard-barrier IS present (P117 evict clean+drained at yield) but insufficient; intra-vs-cross UNRESOLVED"). START HERE.
- `sess12run-DECISIVE-dir-block-doublealloc-with-AG-btree-block-PROVEN` (raw-disk proof: dir data block daddr double-alloc'd with an AG btree block).
- `sess22-DECISIVE-daddr-doublealloc-dirblock-vs-filedata` (daddr 0x78 holds urandom FILE DATA read as dir block).
- `sess37-leaf-rebuild-off-and-AG-freespace-doublealloc-root`.
- `compiled-caw-4node-doublealloc-forceblock` (RESOLVED 4/caw by dir_force_block=0, validated 2/4/8/16).
- `compiled-cc-bnobt-agmeta-double-alloc` + `compiled-bnobt-inode-double-alloc-ccloop` (CAUTION: one thread calls the double-alloc a RED HERRING, real root = stale inode/BMAP — reconcile: at 32 the medium genuinely holds a double-used block, so it's real here, but verify the ALLOCATOR handed out an in-use block vs a stale-map read).
- sess32 memory (`sess32-GPT2-verdict-handoff-checkpoint-iflush-fence`): decisive probe design + notes the dir EX release DOES flush inode+data+leaf (xfs_log_force SYNC + mxfs_dir_flush_data_blocks + ail_drain + blkdev_flush) but the AGF/bnobt/cntbt is coordinated by a SEPARATE AG-DLM — that cross-domain AG free-space is the gap.

### DECISIVE PROBE (RULE 4, sess32 design — build next): at xfs_dir3_data_init (or the block allocator bottom), check whether the daddr being allocated is marked FREE in the AG bnobt/cntbt. If the allocator handed out a block the bnobt says ALLOCATED (or a block currently mapped by this dir's in-core extent map / another inode) → double-alloc CONFIRMED at the allocation site (names the WHICH-side: intra-node stale AG map vs cross-node AG-DLM incoherence). Then fix the AG free-space cross-node coherency: ensure the AGF/bnobt/cntbt is drained on AG-DLM release + invalidated/reloaded on AG-DLM acquire (analogous to the inode-cluster staler) so a grow never allocates an in-use block. Prior AG-freespace fixes referenced: sess42 (b_mxfs_ag_gen), sess43 (in-AIL AG-meta not discarded), sess24/47.

### FIX APPROACH: A/B lazy_ag_drain=0 (and the other AG params) at 32/caw FIRST (cheap, no build) — if any flips it to PASS, that localizes the drain gap. Then implement the AG free-space coherency fix at the proven site. Watch tests/drc_single_node.sh stays CLEAN (delicate-path fixes have SHUT DOWN the FS before — sess32). If own ideas exhausted after evidence, RULE-5 Fable consult warranted (proven arch diagnosis, multi-session-open).

### STATE: cluster CLEAN (run killed, lock cleared). VERSION 0.10.56 (6C932BD7, diagnostic instruments only, all KEEP). Board: 16/17 PASS 32/caw, dir_reuse PENDING (last run killed after harvesting, before record → shows PENDING not FAIL; it FAILs deterministically ~r3-r7). Mechanics/gotchas in sibling memory.
</body>
