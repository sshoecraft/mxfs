---
name: sess51-SHARPEST-mechanism-in-AIL-stale-block-needs-merge-or-drain-on-acquire
description: sess51(ccloop) SHARPEST: divergent RMW root = a dir block that is BOTH locally-dirty/in-AIL (our adds) AND missing a peer's durable entry; evict's ke…
metadata:
  type: project
---

## sess51 (ccloop) — SHARPEST mechanism + fix direction (reconciles ALL evidence)

### The reconciling insight (given force_evict=1 already evicts every modify, yet single-dirent loss persists):
The whole-dir clean-block evict (mxfs_dir_evict_data_blocks, runs every modify) CANNOT drop a dir DATA block that carries THIS node's own committed-but-not-yet-durable entries — it has a hard guard skipping dirty/in-AIL/undestaged buffers (correct: dropping them would RESURRECT/lose our own work). 
But under the storm a single dir block becomes BOTH:
  (i) locally dirty/in-AIL — this node Y added its own dirents to it, not yet destaged, AND
  (ii) STALE — missing a peer node4's dirent `alpha` that node4 added under its prior EX tenure and DRAINED to disk on release (Inv 1), AFTER Y last refreshed this block.
The evict's keep-guard (i) prevents refreshing (ii). Y then RMWs this kept stale-but-dirty block (adds beta) and writes it back → the durable block now has Y's entries + beta but NOT alpha → node4's alpha (which WAS durable on disk) is overwritten. Count-preserving single-dirent loss, no backward-count write (Y's block only grew), all nodes agree. EXACTLY the proven content-timeline signature [[sess51-PROVEN-loss-is-count-preserving-divergent-RMW-phantom-cached-ex]].

### Why pure evict (my reverted attempt) and pure keep both fail:
- Pure evict of the dirty block → loses Y's committed entries (resurrection; the sess26/sess49 readdir=0 / mass-loss family).
- Pure keep (current keep-in-AIL guard) → loses alpha (the single-dirent loss).
The block genuinely needs the UNION of (Y's in-AIL entries) and (the peer's durable entries). It needs a MERGE, not evict-or-keep.

### TWO viable fixes (next session, RULE 4 — instrument first, then ONE at a time):
1. **Drain-own-in-AIL-before-refresh on handoff (preferred, simpler):** when the master epoch advances (genuine handoff detected — mxfs_v5_dlm_inode_dir_epoch > i_dlm_dir_evict_mep), FORCE this node's in-AIL/dirty dir DATA blocks to DISK (xfs_log_force + targeted AIL push of THIS dir's blocks) BEFORE the evict. Then the blocks are clean+durable, the evict can drop them, and the cold re-read fetches disk = (our now-durable entries) UNION (peer's durable alpha) → merged, no loss, no resurrection. Cost: one log_force/AIL-push per handoff (not per op). Watch lock-ordering (don't log_force inside a txn holding ILOCK in a way that deadlocks the peer's drain — see CLAUDE.md ILOCK-across-CAW tension; do it at modify-refresh entry before the txn, or via the acquire path).
2. **Block-level merge (harder):** on detecting a stale in-AIL block at handoff, read the peer's durable image and graft missing dirents into our in-core block (like the shortform sf_merge / dir_write_merge but for block/leaf format). Complex due to XFS dir3_data layout (bestfree, tail, hash). Higher risk.

### Also confirmed this session: my epoch-evict gate change was INERT (force_evict=1 default; see [[sess51-CORRECTION-epoch-evict-was-inert-force-evict-already-1]]); the repro7 mass loss was flaky noise, not my change. GPT's BAST-quiesce/active-ref (mechanism d) is still untried but secondary — the primary is the in-AIL-stale-block merge above.

### STATE: tree = clean baseline C69E3475 (byte-identical, both attempts reverted); cluster rebooted clean; marker NOT written. Tool: dirwr fingerprints (MXFS_EXTRA_MODARGS=dirwr=1 + DRC_STREAM=1). To CONFIRM this mechanism before fixing: add a probe at the dir-EX modify that fires when the target block is (dirty||in_ail) AND b_mxfs_dir_epoch < master_epoch (stale-AND-dirty) for ino 131 — that is the exact clobber condition; correlate with the lost dirent.
