---
name: ccloop-c7ee71c6-sess318-GPT-ruling-incarn-stale-fix-shape
description: sess318 RULE-5 ruling D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512: dontcache retire + fail-closed lookup + ESTALE gates on all file ops incl fault/ge…
metadata:
  type: project
---

# sess318 RULE-5 ruling — INCARN_STALE fix shape (D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512)

GPT ruling (full text in sess318 transcript). Required set:
1. Retire arm (xfs_inode.c:1534): d_mark_dontcache(VFS_I(ip)) BEFORE xfs_irele; keep bounded retries.
2. FAIL CLOSED: after retry budget, lookup returns -ESTALE — NEVER hand the poisoned inode to the VFS. "A retry budget must never become a safety budget after which stale data is allowed."
3. ESTALE gates (poison = MXFS_IF_INCARN_STALE) on: open, read_iter, write_iter, mmap ENTRY, fault path, page_mkwrite, getattr/statx. Prefer one central checked helper + entry checks as defense in depth. ESTALE not EIO (NFS/cluster precedent); mmap faults → SIGBUS via failed fault.
4. d_revalidate: poisoned positive dentry must not validate (-ECHILD fallback in RCU walk). d_prune_aliases alone insufficient (busy dentries survive).
5. Mapping revocation: existing mmaps can read page cache without entering the FS — unmap/invalidate pages (invalidate_inode_pages2 unmaps too) + gate faults; no dirty page may write back through stale bmap.
6. I_DONTCACHE staying set across a racing non-reclaimable cache hit is DESIRABLE (last iput still evicts); fresh/recycled inode must NOT inherit poison or DONTCACHE — verify XFS_IRECLAIM_RESET_FLAGS covers both.
7. Liveness caveat: a long-lived stale FD pins the shell; new incarnation unavailable until close (acceptable — ops on it all ESTALE). Full old/new coexistence (detach from identity cache) NOT required now.

Ledgered as D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 (critical, sess318).
