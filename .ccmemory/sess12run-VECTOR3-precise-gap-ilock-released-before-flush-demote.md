---
name: sess12run-VECTOR3-precise-gap-ilock-released-before-flush-demote
description: sess12(ccloop) vector-3 precise code gap: BAST inode-release releases ip->i_lock (xfs_mxfs_dlm.c:6372) BEFORE the durable flush (6431) + DLM unlock (…
metadata:
  type: project
---

## sess12 (ccloop) — vector-3 precise code gap (for surgical fix next session)

### The serialization gap (xfs/xfs_mxfs_dlm.c, the inode-BAST release function ~5940-7080)
- The drain loop spins to acquire `ip->i_lock` (read) via `mxfs_drain_ilock_read` (down_read_trylock + msleep, UNBOUNDED until it gets it or shutdown) and samples/flushes each dir block UNDER the read lock.
- BUT it `up_read(&ip->i_lock)` at ~line 6372 (and between every block) and then runs the FINAL durability + handoff WITHOUT any inode lock:
  - 6431 `mxfs_dlm_dir_inode_durable(ip)` (the flush: log_force→iflush→delwri→blkdev_flush, ~ms)
  - 7079 `mxfs_v5_dlm_inode_unlock(...)` (the DLM EX demote/release to the peer)
- So AFTER the drain's last up_read, a create thread (xfs_create) grabs `i_lock` WRITE (via mxfs_dlm_ilock_begin) and does addname (P11-DATALOG f15.md5 → daddr 112) WHILE the BAST proceeds to flush+demote. The create's just-added dirent lands on a block the BAST already snapshotted/uncached, and EX is handed to the peer mid-create → durable loss (PROVEN: [[sess12run-BREAKTHROUGH-vector3-BAST-release-races-active-create]]).

### Why the i_lock is released before flush (do NOT naively just hold it across)
The release-before-flush is almost certainly deliberate deadlock-avoidance (the flush does log_force/blkdev_flush and the demote does CAW/DLM unlock; holding i_lock-write across those, or across a CAW poll, is the documented "ILOCK across CAW poll" wedge class — sess33/CLAUDE.md design tension; and sess18 saw DLM rc=-110 timeouts from over-holding). So the fix must serialize WITHOUT reintroducing those.

### Candidate surgical fixes (next session — instrument/test each, watch for DLM -110 + D-state wedge)
1. **Re-check + bounded defer at the unlock point:** right before 7079 unlock, re-probe for an active writer (e.g. `down_read_trylock(&ip->i_lock)` fails == a writer holds it write, OR a new `i_mxfs_dir_writers` atomic set by xfs_create around its addname..durable_signal). If a writer is active, DEFER: re-queue `ip->i_dlm_bast_work` (queue_delayed_work, the existing pattern at 7200/7260) with a small delay and a BOUNDED retry count, and RETURN WITHOUT unlocking. The create's end-of-modify re-kicks. Bounded so a create blocked on a peer AG (AG↔dir ABBA) falls back to today's behavior — no permanent deadlock.
2. **Per-inode `i_mxfs_dir_writers` atomic** incremented in xfs_create/rename/remove AFTER acquiring dir EX + modify_refresh, decremented after durable_signal; BAST checks it (cheaper/clearer than the i_lock probe). Same bounded-defer + re-kick.
3. Pin the DLM grant for the create's transaction so the demote can't run (cleanest conceptually, but needs grant-pin plumbing).

The create-side hook points: xfs/xfs_inode.c xfs_create (after `mxfs_dlm_dir_modify_refresh(dp)` ~line 1499; clear after the commit/durable). Mirror in xfs_rename/xfs_remove.

### This is the DOMINANT dir_reuse failure (single-dirent loss). Fixing it likely makes 4/tcp dir_reuse pass; then fence_during_write corruption-0x8 (separate AG/extent root) remains. Criterion still NOT met. Build 40AC2A0C (2 backstop fixes, no regression). See [[sess12run-GPT-DESIGN-tenure-rebase-dir-coherency-unified]].
</body>
