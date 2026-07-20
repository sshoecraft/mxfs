---
name: sess12run-GPT-DESIGN-tenure-rebase-dir-coherency-unified
description: sess12(ccloop) GPT-5.5 architecture for dir_reuse: per-tenure REBASE (not merge) of whole dir object from UNCACHED dinode read on EX reacquire; defer…
metadata:
  type: project
---

## sess12 (ccloop) GPT-5.5 consult — unified tenure-rebase architecture for dir_reuse_coherency

UNIFIED INVARIANT (subsumes all 3 vectors): a directory's in-core XFS state is valid ONLY for the DLM EX tenure that instantiated it. On EX (re)acquire after a peer may have held EX → REBASE the COMPLETE dir object (i_df fork + dir data/leaf/free buffers + extent map/bmbt) from the durable on-disk image BEFORE the first mutation. On EX release/demote → drain all dirty dir state to home LUN locations, then mark local cache invalid. Tag cached state with a per-inode dir tenure id; reject old-tenure reads-for-modify and writebacks.

### (1) Shortform fix — in-place data-fork REBASE under ILOCK_EXCL (NOT merge, NOT format-compare)
On EX reacquire when tenure advanced: read the durable dinode via an UNCACHED/private metadata read (`xfs_buf_read_uncached`, or reuse `mxfs_pal_bdev_read_plain_bdev` of the inode-cluster block + boffset — already used in mxfs_dir_evict_data_blocks ~L2549) — do NOT trust the cached inode-cluster buffer (may hold a stale prior-tenure copy; cannot blindly xfs_buf_stale it — holds other inodes). Verify (`xfs_dinode_verify`, `xfs_dir2_sf_verify`). If disk di_format==LOCAL: destroy stale `dp->i_df` data-fork contents and replace from the dinode literal area (kmemdup XFS_DFORK_DPTR, set if_format=LOCAL, if_bytes=di_size, if_data=new, update i_disk_size + i_size_write). DO NOT mark dirty (it's a cache rebase, not a local change). DO NOT call the full inode-reload path (avoids down_write(i_lock) deadlock under ILOCK_EXCL). It's a REBASE not a MERGE: valid because Invariant #1 drained the prior EX holder, so the durable disk image is authoritative; any divergent local shortform is stale and must be discarded. Refactor/borrow xfs_iformat_local/_extents/_btree semantics. Gate: only when tenure advanced (else we'd revert our own un-drained current-tenure work).

### (2) Vector 3 (intra-create revert) — order rebase BEFORE addname; defer BAST during writer
Valid order: ilock EXCL → acquire/upgrade dir DLM EX → IF tenure changed: rebase from disk → re-lookup name on coherent base (lookup under PR then EX must re-check; EEXIST vs add) → addname → log → commit → durable_signal → end_modify → unlock. A DLM gen bump / BAST MUST NOT mutate/reload the in-core inode while a create txn is active. Implement a per-dir coherence state machine: begin_modify sets writer_active under a mutex after rebase; BAST during writer_active sets revoke_pending (does NOT reload/demote); end_modify processes the deferred revoke. Pin EX for the whole create. (The observed gen 4→5 mid-create = a reload worker applying a new gen inside the txn — FATAL, must be prevented.)

### (3) Release path
Stop new writers → wait active writer → commit → force log for dir → push AIL until inode+dir buffers reach HOME locations (not just peer's log) → verify no dirty dir buffers/fork remain → mark cache invalid → demote/release. My sess12 ABA write-guard (build B5FB078A, dir_ex_write_guard) is the correct "emergency brake" for old-tenure writeback but the PRIMARY mechanism is: old-tenure buffers must not remain dirty/writeable after EX release.

### Performance: NOT a per-modify FUA read. Fast path (same node still holds EX, cache_tenure==grant_tenure) pays nothing. Cost only at the EX lease boundary (one uncached dinode read + invalidate). The 4-node-bounce-one-dir workload naturally pays more there — correct place to pay.

### Implementation status / next
- Vector 1 (ABA writeback): DONE — build B5FB078A (dir_ex_write_guard=1, KEEP). No regression, but insufficient alone.
- Vector 2 (shortform rebase): IMPLEMENT NEXT — highest value, concrete above. Wire into mxfs_dlm_dir_modify_refresh (xfs_mxfs_dlm.c:3483) BEFORE the data-block evict; for the shortform branch (currently mxfs_dir_evict_data_blocks returns true early for LOCAL).
- Vector 3: needs the begin/end_modify + deferred-BAST state machine.
- ALSO: fence_during_write corruption-0x8 (xfs_defer) is a SEPARATE AG/extent root, still open.

See [[sess12run-THREE-VECTORS-stale-base-RMW-and-ABA-writeback-fix]] [[sess12run-CLEAN-BUILD-4tcp-baseline-two-real-bugs]].
</body>
