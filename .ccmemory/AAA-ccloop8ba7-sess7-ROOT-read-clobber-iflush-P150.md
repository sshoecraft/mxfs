---
name: AAA-ccloop8ba7-sess7-ROOT-read-clobber-iflush-P150
description: sess7 ROOT CAUSE PROVEN (iter_14 full braid): cold READ of inode-cluster w/ attached log items clobbers just-iflushed dinode image → stale nx re-writ…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess7, double-alloc, root-cause, P150]
---

# The double-alloc ROOT CAUSE — proven end-to-end in iter_14 (build B70D745A, 0.10.118 probes)

## Repro
`MXFS_EXTRA_MODARGS=\"dblalloc_probe=1 dirwr=1\" timeout 590 scripts/dblalloc_repro.sh 14` → REPRODUCED on first try (uv=56623258 pm=6291611, OVERLAP fsb 5767463 = AG22/agbno295, cc 31/32). Full journals: tests/logs/dblalloc_repro/iter_14/full_test*.log (1.5M lines). Note: pull journals WITHOUT grep on the base64 stream (grep treats the 748KB single line as binary and eats it) — `$SSH testN pass \"journalctl -k --since 'T0' | gzip | base64 -w0\" 2>/dev/null | base64 -d | gunzip`.

## The braid (all realns-anchored, test3, 23:40:30)
1. rm storm empties uv dir → block→shortform conversion commits (nx 3→0, size 8192→6, chg 1921→1922); extent AG22/295 freed (P145-FREE +0ms).
2. xfsaild iflush copies the NEW image into the cluster buffer: P32-IFLUSH-NXSHRINK incore_nx=0 disk_nx=3 dlm_mode=5 comm=xfsaild + P33-TODISK-DIRSHRINK writing_size=6 writing_nx=0 (both LOG-ONLY probes; P32F-NXSHRINK-FENCE fired 0×).
3. CONCURRENTLY the rm thread (xfs_remove → mxfs_dlm_dir_inode_durable → mxfs_inode_cluster_durable → xfs_imap_to_bp) issues a COLD DISK READ of the same cluster daddr=56517176 — buffer had been STALED earlier by the DLM reload invalidation (\"DLM reload BAIL … buffer staled\"). P20-BIO-READ-LOGGED li_empty=0 comm=rm + stack dump captured it.
4. The DMA clobbers b_addr with the platter's PRE-shrink image (nx=3/8192). xfsaild's queued delwri write then pushes those stale bytes back: P133-DIRINO-WR size=8192 nx=3 comm=xfsaild (+31.6ms) → P136-DIRINO-WRDONE nx=3 (+32.2ms).
5. The flush completion cleans the inode item → ili_fields=0, !in_ail. The nx=0 state now exists ONLY in RAM.
6. test3's release durable loop: P146-RELDUR nx=0 chg=1922 dsize=6 flushed=1 wrote=0 rerr=-11 (EAGAIN=nothing dirty) → releases. P-SFREL-VERIFY prints \"disk_size=8192 STALE-DISK\" (pre-existing probe knew!).
7. Peers adopt platter nx=3: P105-ACQ-DIRINODE disk_size=8192 nextents=3 on every subsequent tenure. The dir's on-disk map durably references 3 freed blocks; posix_multi later legally re-allocates 295 → cross-inode overlap → EFSCORRUPTED dir (`ls` fails, cc-check ghosts).

## Upstream invariant violated
An inode-cluster buffer with attached inode log items is NEVER re-read from disk in stock XFS (always DONE-cached until written). MXFS's cross-node invalidation (reload stales cluster buffers so peer-modified inodes are re-read fresh) breaks it; any cold read then races iflush copy-ins.

## FIX (0.10.119, P150 READ-PRESERVE — read-side mirror of mxfs_submit_partial_inode_write)
- xfs_buf.h: b_mxfs_rd_preserve (kmalloc snapshot) + b_mxfs_rd_preserve_mask.
- pal/linux/xfs_buf.c capture (xfs_buf_submit_ex READ branch, after P20 probe): multi-node inode-cluster read with non-empty b_li_list → snapshot b_addr, mask = slots of attached items whose ili_inode->i_dlm_mode == MXFS_LOCK_EX (EX-only: excludes NL ghosts → no peer-image resurrection).
- __xfs_buf_ioend READ branch (before verify_read): restore masked slots from snapshot (each slot a complete iflush product w/ valid CRC), kfree. P150-RDRESTORE prints ino/nx/chg.
- Error path: snapshot kept for resubmit; freed at xfs_buf_free + cleared at xfs_buf_stale (incarnation end).
- Sibling: mxfs_buf_coherent_reread_verify (CRC-retry whole-copy) merges EX slots from b_addr into the fresh snapshot before install (P150-REREAD-MERGE).

## Instrumentation added in 0.10.118 (keep)
P146-RELDUR (durable-loop exit: nx/chg/flushed/wrote/rerr/in_ail/pin/ili_fields/realns), P147-PREUNLOCK (both unlock arms), P105 high-ino arm un-ratelimited + chg, P56-CORESIDENT-DIR-SKIP capped+identity. All ungated; P136/P105/P20 need mxfs.dirwr=1.

## Next
Validate: repro iters with dirwr=1 on 0.10.119 — expect P150-RDRESTORE fires, NO new overlap/foreign, cc 32/32. Then ladder 32/caw full, 16/8/4/2/1 regression, budgets, criteria marker. Family-A post-rmmod panics still open (sess6 memory).
