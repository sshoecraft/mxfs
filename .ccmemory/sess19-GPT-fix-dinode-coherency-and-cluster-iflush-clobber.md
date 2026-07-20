---
name: sess19-GPT-fix-dinode-coherency-and-cluster-iflush-clobber
description: sess19 GPT-5.5 fix direction for 2/tcp dinode-revert loss: treat dir dinode+fork as the DLM coherency payload (invalidate-on-revoke, authoritative re…
metadata:
  type: project
---

## sess19 GPT-5.5 consult (RULE-5, escalation GPT-first) on the dir-dinode-reverts-to-stale-shortform durable loss [[sess19-dinode-reverts-to-stale-shortform-confirmed]].

## GPT VERDICT (decisive): do NOT merge dirents; do NOT suppress writes by tenure-stamp (both refuted). Treat the XFS dir DINODE + data fork (di_format LOCAL/EXTENTS/BTREE, di_size, di_nextents, extent root, if_data) as ONE atomic coherency payload of the directory DLM lock — exactly like a GFS2/OCFS2 inode glock/cluster-lock. Protocol:
1. DRAIN all dirty/logged dir-inode metadata before DLM unlock (Invariant #1, mostly in place).
2. On revoke/demote: mark the in-core dir dinode/fork INVALID (NEED_REFRESH) AND invalidate the cached INODE CLUSTER BUFFER holding this dinode. Must happen AT/BEFORE unlock, not lazily.
3. On next EX grant: AUTHORITATIVELY re-read the on-disk dinode (uncached/coherent) and rebuild ip->i_df (format+extents/sf+di_size) BEFORE any dir op. Do NOT preserve old shortform fork, do NOT union.
4. Write-side: allow xfs_trans_log_inode/xfs_iflush/sf_to_block/block_to_sf only when EX-held AND current-for-this-grant; else it's a protocol violation (a stale dir inode must never become dirty). This is a coherency ASSERTION, not tenure-stamp suppression.

## THE NEW LEVER (#5, likely THE clobber mechanism, not addressed in sess<=18): XFS xfs_iflush_cluster() flushes MULTIPLE inodes from ONE inode-cluster buffer and submits the WHOLE buffer. The dir inode 1962 shares a cluster with the md5/data file inodes both nodes create. When node A iflushes a NEIGHBORING inode (an md5 file) in that cluster, it uses node A's CACHED cluster buffer whose slot for dir 1962 holds node A's STALE shortform image (node A isn't actively modifying 1962, so that slot isn't patched) → submitting the buffer durably writes the stale shortform 1962 dinode over the peer's block-format one. Fits the evidence exactly (lost entries are md5 sidecars = neighboring inodes; dir reverts to shortform-1). FIX: on multinode mounts, before iflush submit, RE-READ the cluster buffer fresh/coherent so non-actively-modified slots reflect the durable image, patch only this node's dirty inodes, then write; OR constrain/disable xfs_iflush_cluster to only write currently-granted inodes; OR DLM-lock the inode cluster buffer.

## NEXT (implement, RULE 4 — instrument first to PROVE the cluster-iflush clobber, then patch): examine xfs_iflush/xfs_iflush_cluster + existing MXFS inode-cluster coherency hooks (CLAUDE.md v0.4.9: invalidate stale cluster buffer on multi-node cache-miss read — sess38). Add a detector: log when an iflush cluster-buffer write includes a dir-inode slot whose in-core image (or buffer slot) is stale vs disk. Validate: cc_blockdir_probe 0 loss >25 iters + ./run.sh 2 tcp 16/16 ×>=3. Watch canaries: rename/unlink_visibility, cross_write_read.
