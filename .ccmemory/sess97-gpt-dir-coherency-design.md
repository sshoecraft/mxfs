---
name: sess97-gpt-dir-coherency-design
description: sess97 GPT consult: robust dir read-coherency design = durable per-dir SEQLOCK EPOCH (odd=writer active/even=published) pulled synchronously by reade…
metadata:
  type: project
---

# sess97 GPT consult — robust DIRECTORY read-coherency design (CAW transport)

Context: writer side FIXED (publish-before-notify, rename PASS, build 476E164C). Remaining = peer reader dir-block staleness (restamp-with-stale-read + unreliable EVICT-RING heartbeat). See [[sess97_lessons]].

## GPT verdict (ranked)
1. **BEST = (C) shared durable per-directory EPOCH as a SEQLOCK**, read synchronously by readers on every lookup/readdir. Make it the AUTHORITATIVE coherency mechanism; stop relying on heartbeat/EVICT-RING for correctness (keep it only as a perf hint).
2. **(B) restamp fix is REQUIRED but insufficient alone**: reread FIRST, stamp `b_mxfs_dir_epoch = observed_durable_epoch` AFTER the reread completes — never before.
3. **(E) unconditional invalidate+reread = correct fallback / paranoid mount mode**, not default (perf wall on hot dirs).
4. **(A) fresh-PR-every-dir-read = NOT sufficient alone + too expensive unconditional** under CAW (disk-poll latency per read). Use only on epoch-odd/stuck/recovery path.
5. **(D) per-block/LSN gen = phase-2 optimization**, not needed for correctness once epoch exists.

## SEQLOCK semantics
`seq` even = stable published image; odd = writer in progress. Reader trusts dir buffers only if `bp->b_mxfs_dir_epoch == dp->i_observed_epoch`.

## Storage (v1): CAW/DLM lock-resource record (LVB)
Per-inode DLM resource already shared on-disk; add an epoch field. Read/write via RAW plain bio (REQ_OP_READ/WRITE, bounce page) — NOT bread()/xfs_buf (that re-creates the stale-cache problem). NO FUA (fua_disable=1; plain reads coherent once writer bio completes). Longer-term: mkfs-reserved coherency area / hidden inode / per-AG table keyed by dir ino.

## Writer protocol (every dir-modifying op: create/unlink/rename/mkdir/rmdir/link)
1. Acquire dir DLM EX.
2. Publish ODD: seq = E+1, wait write completion (writer active).
3. XFS transaction.
4. xfs_trans_commit().
5. xfs_log_force(SYNC).
6. bwrite ALL modified dir-visible metadata to target (data + leaf + node + freeindex/freespace + dabtree + inode core/extents if changed): for each buf → xfs_buf_wait_unpin + xfs_bwrite + wait.
7. Publish EVEN: seq = E+2, wait completion (stable published).
8. Release DLM EX.
Guarantee: reader sees EVEN E+2 ⇒ all E+2 dir blocks completed to target cache BEFORE epoch E+2 written. Ordering only (bio completion), no FUA.

## Reader protocol — `mxfs_dir_read_coherency_envelope(dp)` at TOP of lookup/readdir/dir_lookup/dir2_readdir (before XFS uses cached extent map/buffers)
```
seq = raw_read_dir_epoch(dp)        // raw plain bio, no FUA
if (seq & 1) { release; msleep(1); retry }   // writer active — don't trust cache
if (seq != dp->i_observed_epoch) { reload dinode+ifork; mark dir buffers stale(target=seq); }
dp->i_epoch_target = seq
```
Buffer read hooks (xfs_da_read_buf, xfs_dir3_data_read, xfs_dir3_leaf_read, xfs_da3_node_read, freeindex reader):
```
if (bp->b_mxfs_dir_epoch != dp->i_epoch_target) {
   lock bp; wait local unpin; verify NOT locally dirty; clear XBF_DONE; submit PLAIN read; wait; run verifier;
   THEN bp->b_mxfs_dir_epoch = i_epoch_target;   // stamp ONLY after reread
}
```
This makes "stamped with epoch E ⇒ content ≥ as fresh as E". Cross-writer conflation gone (epoch = serialized per-dir publish point, not per-node heartbeat). Must invalidate MORE than data blocks (leaf/node/freeindex/dinode/extent map).

## PR/EX BAST: keep for mutual exclusion + local op structure, but it must NOT imply "dir cache fresh." sticky PR = lock fast path; durable epoch = freshness path.

## Default policy: mount opt `mxfs.dir_coh=epoch`. Writer writes odd before mutation, even after all dir metadata bwrite completes. Reader raw-reads epoch each lookup/readdir; same even → cached; newer even → reload+lazy-reread+stamp-after; odd → poll/recover.

## My implementation plan (incremental, measure each)
- Phase 1 (contained, validate approach): fix restamp (reread-before-stamp) + a dir read-coherency envelope that forces fresh-PR/eager dir-buffer evict on readdir/lookup (mirrors proven regular-file mxfs_read_coherency_envelope which is a NO-OP for dirs today). Measure correctness + perf.
- Phase 2 (if fresh-PR too slow): add the durable epoch (LVB) to gate the fresh-PR so unchanged dirs stay cheap.
- Regular-file envelope already works under CAW ⇒ CAW BAST/demote DOES function for files; dirs differ because reload bumps lazy i_dlm_dir_gen (restamp-prone) instead of eagerly evicting dir xfs_buf like files drop page cache. Eager dir-buffer evict on reload is the file-parity fix.
