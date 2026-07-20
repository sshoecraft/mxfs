---
name: sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss
description: sess52(ccloop) ROOT CAPTURED: dir_reuse readdir=799 = xfs_dir2_node_addname RMW of a stale-epoch (b_epoch<valid_epoch) cached DATA block; read-gate m…
metadata:
  type: project
---

## sess52 — readdir=799 ROOT path captured on current build (236772FA)

### What's REFUTED this session
- `dir_ex_revalidate=1` (sess51 "breakthrough"): REFUTED. Fresh cold-reboot run → round-16 readdir=799 durable loss (node3_f22.md5, dirino=131 same on all nodes, disk_gen==incore_gen sameincarn=1 = node3 adopted clobbered disk). repro9's 8/8 was a ~25% flaky fluke.
- `dir_write_merge=1`: WEDGES cluster (barrier desync ~round16). Harmful.
- GPT consult #1 (release-side EX-demotion barrier: log_force SYNC + ail_push to completion + invalidate + blkdev_flush): **ALREADY FULLY IMPLEMENTED + ON** (release fence ~xfs_mxfs_dlm.c:9557, unbounded data_durable loop + 15s shutdown backstop; `dir_release_ail_all` whole-AIL push PROVEN sess44 NOT the fix). Release durability is NOT the gap.
- `dir_modify_target_flush=1` (SYNCHRONIZE CACHE post-evict) + FUA read/write + `dir_no_reada=1` (readahead off) + `dir_gen_per_handoff=1`: ALL already default-ON. Every "standard" coherency fix is implemented; bug persists ~25%.

### ROOT (PROVEN, P-STALEBASE-MODIFY probe + dump_stack, GPT consult #2)
Added a probe in `xfs/libxfs/xfs_dir2_data.c:xfs_dir2_data_log_entry` BEFORE the sess16 stamp (`bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch`): if `bp->b_mxfs_dir_epoch != 0 && < dp->i_dlm_dir_valid_epoch` (stale base) → pr_warn + one-shot dump_stack. **Fired 12×** across nodes in one run (gated mxfs.dirwr=1, ino<=256).
- Sample: `P-STALEBASE-MODIFY ino=131 daddr=6279744 b_epoch=115 valid_epoch=119 name=[node3_f41.md5] comm=bash` — block last coherently read at epoch 115, but 4 cross-node handoffs happened since (valid_epoch=119); this node's cached copy of that DATA block was NEVER re-read, and addname RMW'd the epoch-115 image.
- STACK: `xfs_dir2_data_log_entry ← xfs_dir2_data_use_free ← xfs_dir2_node_addname ← xfs_dir_createname_args ← xfs_dir_createname ← xfs_dir_create_child ← xfs_create`. **NODE-FORMAT dir.** addname's free-index search picks a DATA block with a "free" slot; reads that DATA block (stale cached image); the slot is free only in the STALE image (a peer filled it on disk) → durable clobber of the peer's dirent.

### The MASKING bug (xfs_dir2_data.c ~line 1283-1290)
The sess16 MODIFY-time stamp UNCONDITIONALLY sets `b_mxfs_dir_epoch = valid_epoch`, laundering a stale base into "current tenure". So downstream epoch guards (P34-DRAIN-EPOCHSKIP `bgen<valid_epoch`, P16-DIRBLK-SUBMIT) see `bgen==dgen` (`would_skip=0`) and let the clobbering write through. Confirmed: `P16-DIRBLK-SUBMIT owner=131 ops=xfs_dir3_data bgen=59 dgen=59 would_skip=0`.

### WHY the read gate misses (next: FIX target)
The read-path invalidation re-reads a cached dir block only when `b_mxfs_dir_gen < i_dlm_dir_gen` (GEN, not EPOCH). The NODE-addname DATA-block read either (a) hits a buffer already in the txn buffer list (xfs_trans_read_buf cache-hit, no gate), or (b) the gen check passed because gen was stamped == this tenure on a prior op while epoch lagged. The EPOCH (b_mxfs_dir_epoch) correctly shows staleness but is NOT consulted by the read gate.

### FIX DIRECTION (GPT #2, to implement+test next)
Make the dir DATA-block read in the addname/free-index path force a coherent re-read when `b_mxfs_dir_epoch < i_dlm_dir_valid_epoch` (epoch-based gate), NOT just gen. Hook xfs_da_read_buf / xfs_dir2_data_read coherency check to also consult epoch. Must cover NODE-format free-index-selected DATA blocks. Alternative: at EX acquire, purge-by-physical-extent ALL dir blocks (data+leaf+free+node) so the free-slot search operates on coherent data. Keep the P-STALEBASE-MODIFY probe (gated dirwr) as the regression detector — it must reach 0 hits.

See [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]] [[sess26-DECISIVE-evict-always-evicts-base-is-postevict-stale-read]]. Build 236772FA carries the probe (gated, baseline-equiv when dirwr=0).
