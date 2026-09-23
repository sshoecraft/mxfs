---
name: trap-an-igrab-held-by-async-work-does-not-keep-an-uninserted-iget-miss-inode-alive
description: TRAP (s166): xfs_iget_cache_miss's out_destroy frees an uninserted inode ignoring i_count; any work queued on it with an igrab ref runs on freed memo…
metadata:
  type: feedback
tags: [inode-lifetime, iget, use-after-free, workqueue]
---

Anything that runs inside `xfs_iget_cache_miss` before the radix insert can hand the new inode to async work: a DLM acquire, or a coordinated reload such as the P127 ENOENT arm or the verify-fail arm. The same function's error exit (`out_destroy`: `__destroy_inode` + `xfs_inode_free`) frees that inode directly and ignores `i_count`. So an `igrab` taken by the async work does NOT keep the inode alive.

- The BAST works are embedded in the inode, and `out_destroy` reaps them with `cancel_work_sync` (sess6).
- A separately allocated work item, like the incarnation revocation (`mxfs_incarn_poison`), cannot be reached from there. Its worker later locks, prunes and `iput`s freed or reused memory.
- Field signature: `BUG_ON(I_CLEAR)` at `iput+0x1c5` from `mxfs_incarn_revoke_work_fn`, node panic.
- On-demand signature (`dbg_poison_direct_free`, `tests/revoke_direct_free_repro.sh`): a page fault in `d_mark_dontcache` under the worker.

Rule of thumb: before queuing work that holds an inode reference, ask whether the object is the radix-current inode for its number (the `radix_tree_lookup` under `mxfs_ici_lock`). An uninserted object has no page cache and no mappings, so any work meant to revoke them is unnecessary there.

Fixed in 0.89.75 (D-TCP-INCARN-REVOKE-WORKER-IRELE-HITS-IPUT-BUG-NODE-PANIC).
