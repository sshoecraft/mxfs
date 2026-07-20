---
name: sess12run-VECTOR3-precise-BAST-site-14430-defer-during-create
description: sess12(ccloop) vector-3 precise trigger: BAST handler xfs_mxfs_dlm.c:14430 (MXFS_EVICT_TYPE_DIR_MODIFY) bumps i_dlm_dir_gen + arms MXFS_IF_DIR_RELOAD…
metadata:
  type: project
---

## sess12 (ccloop) — VECTOR 3 (intra-create single-dirent revert) precise trigger located

### Mechanism (ties sess11 DECISIVE gen 4→5-during-create to a code site)
1. A create holds dir ILOCK_EXCL; runs modify_refresh (evict) → addname (rval=0).
2. A PEER modifies the same dir → sends a DIR_MODIFY eviction notification.
3. Our BAST handler at **xfs/xfs_mxfs_dlm.c:14430** (`if (type == MXFS_EVICT_TYPE_DIR_MODIFY)`) bumps `i_dlm_dir_gen` (the 4→5 bump) and arms `MXFS_IF_DIR_RELOAD` (sess54: for EVERY dir format). It holds only spinlocks, so it can only flag.
4. The create thread's OWN subsequent `xfs_da_read_buf` (leaf/data read during addname's split/rebalance) or the durable_signal path then CONSUMES the armed gen/flag → invalidates/cold-reads the peer image → REVERTS the just-added dirent (gone from in-core at durable_signal, same thread, ILOCK held — exactly sess11's DECISIVE signature).

### FIX (GPT vector-3 design): defer the reload/gen-consumption while a create txn is active
The BAST may FLAG intent but the in-core dir state must NOT be reloaded/invalidated/reverted while an XFS create/modify transaction is active on that inode. Options:
- Per-dir `writer_active` flag set in a begin_modify (after modify_refresh, before addname) and cleared in end_modify (after durable_signal). While set: xfs_da_read_buf's gen-invalidation hook AND the MXFS_IF_DIR_RELOAD consumption must NO-OP (skip the mid-txn reload); the reload runs at end_modify if revoke_pending.
- The create's modify_refresh already gives a coherent base at the START; the peer's mid-create change must be adopted on the NEXT modify, not by reverting THIS one.
- Caution: deferring the reload means our addname proceeds on the pre-BAST base and commits; that's correct (we hold EX for the duration; Invariant #1 drains before we actually yield). The peer's BAST handoff (drain+demote) must wait for writer_active to clear (do NOT demote mid-create) — verify the demote path already waits on ILOCK_EXCL (it should, since we hold it).

### Decisive probe if needed before fixing: add a timestamp + comm + current->journal_info at the 14430 gen-bump AND at every xfs_da_read_buf gen-invalidation consumption, scoped to the storm dir ino; confirm a consumption fires BETWEEN the create's addname and durable_signal in the SAME thread. sess11 already strongly implies this; one capture confirms.

### Watch for regressions: deferring reloads must not (a) wedge the dir-EX handoff (peer waits — sess18 saw DLM -110 timeouts from over-holding), (b) leave MXFS_IF_DIR_RELOAD permanently armed. Clear+process it at end_modify.

See [[sess12run-RESULT-vector1-2-fixes-sound-but-inert-vector3-dominant]] [[sess12run-GPT-DESIGN-tenure-rebase-dir-coherency-unified]] [[sess11run-DECISIVE-dirent-absent-at-durable-signal-entry-handoff-during-create]].
</body>
