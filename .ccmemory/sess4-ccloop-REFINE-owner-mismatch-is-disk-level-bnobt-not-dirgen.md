---
name: sess4-ccloop-REFINE-owner-mismatch-is-disk-level-bnobt-not-dirgen
description: sess4(ccloop run6614) DECISIVE REFINEMENT: the dir-block owner-mismatch shutdown is a REAL DISK READ (xfs_buf_submit→ioend) returning ANOTHER live in…
metadata:
  type: project
---

## sess4 (run 6614aa96) — the owner-mismatch is DISK-LEVEL, not an in-core dir-gen miss

### DECISIVE (P-BLKRV dump_stack, build 0FB8EBA3)
The shutdown read goes: `xfs_dir3_block_read → xfs_da_read_buf → xfs_buf_read_map → xfs_buf_submit → __xfs_buf_ioend → read_verify FAIL`. That is a REAL DISK I/O completing, and the buffer holds ANOTHER live dir inode's valid dir3 block (owner=4194437 while reader=4194432) OR garbage. So the physical block (daddr 120 / 4186568) is genuinely allocated to TWO inodes ON DISK = **bnobt double-allocation**, not a stale in-core buffer.

### THEREFORE (rules out a class of fixes)
- `mxfs_dir_conv_genbump` (conversion-site dir-gen bump) is DEFAULT 0, only wired at `xfs_dir2_block_to_leaf` (NOT sf_to_block), and sess36 refuted it for the loss. It bumps an IN-CORE gen to stale IN-CORE buffers — it CANNOT fix a block that is double-allocated ON DISK. Do NOT chase dir-gen / conversion-bump / invalidate-lever schemes for this shutdown.
- Same for the in-core reload/adopt guards — the disk itself is wrong.

### THE FIX IS AG FREE-SPACE (bnobt) COHERENCE — owner-side, TCP
Node A allocates daddr D for dir inode X (grows/sf→block), commits, RELEASES the AG. Node B fresh-acquires the AG and its bnobt still shows D free → allocates D for dir inode Y → double-alloc → shutdown. The acquirer's read path is thoroughly invalidated (sess40/93/117 coldread on every fast/slow acquire), so the gap is OWNER-SIDE: node A's AG release does not make the bnobt allocation of D DURABLE on disk before yielding the AG (Invariant 1 for AG-meta on the TCP path), so B reads a stale bnobt. sess46 reached the same conclusion (real fix is owner-side / not acquirer read path).

### NEXT SESSION — instrument the AG RELEASE drain (RULE 4)
At AG EX release (bast_work_fn Phase 2 drain → mxfs_v5_dlm_ag_unlock), verify the bnobt/cntbt/AGF buffers reflecting THIS tenure's allocations are actually written to disk BEFORE the unlock. Repro that double-allocs: `MXFS_EXTRA_MODARGS='dir_force_block=0' ./run.sh 4 tcp dir_reuse_coherency` (~25-50% fail) or `./run.sh 2 tcp cache_coherency` at DEFAULT force_block=1 (mostly fail ~34s, P-BLKRV owner-mismatch). Log, at the allocation of daddr D, whether D was recently freed by a peer whose free isn't durable; and at release, the in-AIL/undestaged state of the bnobt block covering D.
See [[sess4-ccloop-HANDOFF-full-column-status-and-next-step]] [[sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root]] [[sess46]]
