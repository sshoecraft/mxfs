---
name: sess15-PIVOTAL-loss-requires-inode-daddr-reuse
description: sess15 PIVOTAL: 2/tcp block-dir dirent loss REQUIRES inode/daddr REUSE (ABA). No-reuse probe 40/40 clean; reuse probe loses <15 iters. NOT a fresh-di…
metadata:
  type: project
---

## sess15 PIVOTAL FINDING (build CE99583D, dirwr=1, RULE 4 controlled experiment).

## THE LOSS REQUIRES INODE/DADDR REUSE (ABA). Two probes, SAME concurrent-create workload, differ ONLY in reuse:
- tests/cc_minrepro.sh — each iter a FRESH never-removed dir (.mr_$it), no rm → NO inode/daddr reuse → **40/40 iters CLEAN (0 loss)**.
- tests/cc_blockdir_probe.sh — each iter mkdir .ccb_$it then `rm -rf` at end → frees inode+data blocks → next mkdir REUSES → **loses in <15 iters every run** (confirmed iter 9 on this build).

=> The block-dir concurrent-create dirent loss is NOT a fresh-dir concurrent-RMW lost-update. It is an ABA / reused-daddr cross-node cache-coherency bug: when a dir inode (and its data blocks at daddrs D1,D2…) is FREED and a new dir REUSES the inode number and/or those daddrs, a peer still holds the PREVIOUS incarnation's dir DATA block cached at the same daddr (XBF_DONE, daddr-indexed buffer cache). The new incarnation's RMW reads/writes that stale buffer (no I/O since XBF_DONE) → the new dir's just-created dirents in that block are durably dropped.

## WHY prior fixes here DIDN'T work (all this session): master double-grant (P-DOUBLEGRANT=0), MHT (mht=0), sf_merge (=0), and dir_force_evict=1 — none touch the freed-block/reused-daddr invalidation. force_evict drops CLEAN cached blocks for the CURRENT inode's extents, but a reused daddr's stale buffer belongs to a DIFFERENT (freed) incarnation / inode, so it isn't in the current inode's extent walk → not evicted.

## EXISTING PARTIAL FIX: sess104 ABA guard (xfs_mxfs_dlm.c modify_refresh/consumer_refresh: evict when i_dlm_dir_evicted_incarn != VFS i_generation) keys on the INODE's i_generation — catches inode-number reuse on the SAME inode but NOT daddr reuse where a block freed from dir A is reallocated to dir B (B's cache at that daddr is stale, A's gen irrelevant). The eviction-ring (mxfs_v5_dlm_note_inode_freed / note_dir_modified → disklock heartbeat) is the intended cross-node free signal but is LOSSY on TCP (sess10). mxfs_v5_dlm_inode_held = no-op on TCP.

## NEXT (RULE 4): build a reuse-SCOPED probe (per-iter dmesg clear + force rm/reuse) to capture the lost block's daddr and PROVE a node reads/writes a stale prior-incarnation buffer at that daddr. Then FIX: reliable cross-node invalidation of cached buffers for FREED blocks/inodes on TCP — likely (a) on block free (xfs_trans_binval / xfs_free_extent) publish the freed daddr range to peers via a RELIABLE channel (DLM-coordinated, not lossy heartbeat) so peers xfs_buf_stale the daddr; or (b) on dir-block READ, validate the cached buffer's owner-inode/gen in the dir3 block header (XFS_DIR3_DATA has di owner) against the expected inode — invalidate on mismatch (ABA detect at read). GPT's epoch idea applies. Check xfs/libxfs free-extent path + mxfs_dlm_note_inode_freed consumers. Real criterion test crash_consistency does mkdir/rm churn ⇒ hits reuse. [[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]] [[sess15-decisive-negatives-blockdir-loss]] [[sess55-faceB-is-M2-stale-bmap-not-allocator]]
