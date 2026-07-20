---
name: sess-tcp-FINDING-stale-iflush-is-under-EX-not-NL
description: DECISIVE (build C180A702): P-STALE-IFLUSH-NONEX=0 both nodes → node2 flushes its stale dir fork (block0→112) UNDER EX at release-drain, NOT via NL/PR…
metadata:
  type: project
---

## dir_reuse 2/tcp — fence design REFINED (build C180A702, = 2045BCE9 + P-STALE-IFLUSH-NONEX detector). FAIL, marker NOT written.

### DECISIVE RESULT: stale dir-fork flush happens UNDER EX, not in NL/PR.
Added detector in xfs_iflush (xfs/xfs_inode.c, just before xfs_inode_to_disk @~4860): logs P-STALE-IFLUSH-NONEX when a multi-node DIRECTORY inode fork is flushed while `i_dlm_mode != MXFS_LOCK_EX`. Ran drc_cap2.sh (FAIL 0/2) → **P-STALE-IFLUSH-NONEX = 0 on BOTH nodes**. So:
- node2's stale fork (block0→daddr 112) is serialized to the canonical dinode **WHILE node2 holds EX** (release-drain / publish-before-notify path), NOT by a background xfsaild flush in NL.
- => GPT Step-4 fence "forbid flush unless holding EX" is INSUFFICIENT (the stale flush IS under EX).

### THEREFORE the fix is the RELOAD/EPOCH path (GPT Step 1+2), not the simple EX-fence:
node2 holds EX legitimately but its in-core extent map is from a PRIOR incarnation (block0→112). It modifies+flushes that stale map under EX. The fence must be epoch-aware: **do not flush (serialize) a shared dir fork whose loaded epoch != the current canonical epoch, EVEN under EX** — and/or reload-on-EX-acquire must RELIABLY reconcile block0's daddr to the canonical 120 before any modify.

### THE HARD CORE (circularity): node2's reload reads disk; disk oscillates 112↔120 (whoever wrote the dinode last). node1 ALWAYS writes block0→120 (allocator). node2 NEVER allocates block0 but writes block0→112 (its stale in-core map). To break: node2 must STOP ever writing 112. That needs its in-core fork reconciled to 120 and an epoch fence so a stale (epoch<canonical) fork is never serialized. Bootstrap question still open: how node2 FIRST got block0→112 (early-round allocation? first iget of reused ino=131?). The epoch fence makes it self-correcting regardless of the seed.

### NEXT (next session): implement GPT Step 2+4 with the EXISTING gen fields:
- Stamp: fork is "canonical-valid" iff `i_dlm_dir_loaded_gen == i_dlm_dir_gen` AND reloaded since peer's last write. (But the evict-ring that bumps i_dlm_dir_gen is asymmetric/lossy — node1 gets 0 — so gen may be unreliable; may need a real per-dir LVB/epoch in the DLM grant, not the ring.)
- Fence: in xfs_iflush before xfs_inode_to_disk, for a multi-node dir, if the fork is NOT canonical-valid, SKIP the data-fork serialization (write core only, or requeue) — start as ASSERT/pr_warn to confirm it catches the block0→112 write, then enforce.
- Reload: mxfs_dlm_reload_inode must reliably rebuild to the canonical block0 daddr on EX acquire (verify it isn't reading node2's self-stale disk image; may need to gate node2's own block0 write on a fresh reload).
Detector P-STALE-IFLUSH-NONEX is gated dirwr/instr (kept). [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]] [[sess-tcp-FIX-entrypoints-inode-flush-fence]] [[sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr]]
