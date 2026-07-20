---
name: sess43-dirdata-pin-rootcause
description: sess43 PROVEN: concurrent_touch lost-update = release path drains inode cluster but NOT the dir-DATA block's CIL pin before DLM unlock → peer reads s…
metadata:
  type: project
---

## PROVEN root cause (RULE 4 step 2b) — criterion #19 last correctness blocker

Build 7BD3933D (P136 rescue, no shutdowns). From a VERIFIED-CLEAN cluster
(orphans killed first), full `--phase cluster`:
- `test_concurrent_mkdir` PASS.
- `test_concurrent_touch` **FAIL: 1599/1600** (1 lost file) AND **225s** wall
  (native = seconds; RULE 0 perf FAIL too).
- Standalone `--test test_concurrent_touch/mkdir` on a warm cluster PASSES — the
  loss is an intermittent RACE that needs the cold full-phase first-barrier
  contention to fire. DO NOT trust standalone PASS.

### Always-on evidence (no instr build needed — already in tree)
Aggregated across all 16 nodes after the failing run:
- **DIR-STALE-SKIP ~30×/node** (~480 total) — the lost-update window.
- **SESS50-STARVE ~20×/node** (~330 total) — the 225s slowness.

Decisive DIR-STALE-SKIP fields (shared touch dir `ino=18874858`, blk=1/6/0x1000000):
`buf_gen=0 inode_gen=61 dirty=0 in_ail=0 pin=1 delwri=0 has_bli=1 li_empty=1
bli_flags=0x2`.

### The mechanism (resolves the old "pinned = our work, preserve it" tension)
The cached dir block is BOTH stale (buf_gen=0, peers advanced i_dlm_dir_gen to 61
= we re-acquired-after-BAST 61×) AND pinned (pin=1, our own prior dir-modifying
txn is committed-but-uncheckpointed in the CIL). The gen-invalidation hook in
`xfs_da_read_buf` (xfs/libxfs/xfs_da_btree.c ~L3055) correctly REFUSES to refresh
a pinned buffer (refresh would discard our committed-unwritten entries —
sess43/64 proved re-reading a pinned/dirty/in-AIL buf → SHUTDOWN_CORRUPT_INCORE).
So a MODIFYING read (tp != NULL, the touch/create addname path) RMWs the stale
gen-0 base that is missing peers' 61 generations of entries → on commit it writes
a block missing a peer's dirent → durable lost file.

WHY pinned survives 61 releases: each release SHOULD drain per Architectural
Invariant #1 (drain before unlock). `mxfs_inode_cluster_durable` log_force+
iflush+bwrite's the INODE CLUSTER, and mxfs_dir_flush_data_blocks/push_data_ags
handle dir DATA blocks — but the dir-DATA block's **CIL pin** is evidently NOT
checkpointed+written before the DLM unlock on the contended release path, so the
buffer stays pinned at gen 0 in our cache while the lock ping-pongs. (Note one
stale blk = 0x1000000 = a high dablk, likely a leaf/free-index block — check
whether the dir-DATA drain covers ALL of the dir's data-fork blocks, not just
block 0/the data blocks it knows about.)

### FIX DIRECTION (next session — implement with fresh context)
Make the EX-RELEASE drain for a block/leaf/node-format dir guarantee EVERY
dir-DATA-fork buffer is UNPINNED (CIL checkpointed via xfs_log_force(SYNC)) AND
written to the SCST cache BEFORE `mxfs_v5_dlm_ag/inode_unlock`. i.e. extend the
release path so a peer's next plain (fua_disable=1, cache-coherent) read always
sees our durable dirents. Candidate sites: the dir-inode BAST release in
xfs_mxfs_dlm.c (mxfs_dir_data_durable / mxfs_dir_push_data_ags), the noino BAST
path (already bounded-AG-drains, sess88), and mxfs_dlm_evict. Verify the drain
iterates the dir's full data-fork extent map and waits xfs_buf_ispinned()==0 +
writes each, not just !in_ail. PROVE the fix by re-running the cold full
`--phase cluster` and confirming DIR-STALE-SKIP drops to ~0 and count=1600/1600.

The 225s SESS50-STARVE slowness (16-node barrier EX-starvation, sess50 family) is
the SECOND blocker (RULE 0) — likely eases once the stale-read loop stops
churning the lock, but may need its own fix (force a zero-PR window for the EX
waiter; defer_for_waiter only covers FRESH acquires).

Methodology: ALWAYS kill remote orphans (pkill -f "run_tests|mxfs_test|find
/mnt|touch ") + full cluster_reset_n.sh 16 before trusting a result. See
[[sess43-scst-unwedge-and-p136]] for SCST host-wedge recovery + P136 details.
