---
name: sess-tcp-WHY-merge-misses-it-EX-held-stale-incarnation-fork
description: WHY the existing mxfs_iflush_cluster_merge_dirs doesn't fix dir_reuse: it overlays FOREIGN dir slots only; node2's dir inode is EX-held (dirty_seq==e…
metadata:
  type: project
---

## dir_reuse 2/tcp — why the existing co-resident-cluster merge doesn't catch it (deepest analysis, build AFE4E833)

### The cluster-false-sharing mechanism (sess61, xfs/xfs_inode.c:5071 mxfs_iflush_cluster_merge_dirs) IS the right area:
The dir inode (ino=131) shares its 64-inode cluster buffer with the regular-file children (node1_f*/node2_f*). node2 creates 50 files → constantly flushes dirty CHILDREN via xfs_iflush_cluster, which writes the WHOLE cluster — carrying node2's dir slot. That is why the stale dir-fork flush is "under EX of a child", and P-STALE-IFLUSH-NONEX=0 (the DIR isn't the flush target; a child is).

### WHY the merge's overlay does NOT fix it:
merge_dirs overlays FOREIGN inode slots (not flushed this round, not EX-held-current) with the durable on-disk image. Authority gate (line 5149-5152): a slot is treated as AUTHORITATIVE (left in `flushing` mask, NOT overlaid) iff `MXFS_IF_DLM_RELFLUSH || (i_dlm_mode==EX && i_mxfs_dirty_seq==i_mxfs_ex_grant_seq)`.
- node2 IS holding the dir EX and modified it THIS tenure (dirty_seq==ex_grant_seq), so node2's dir slot is treated as AUTHORITATIVE → NOT overlaid → node2's in-core fork (block0→112) is written to the cluster → reverts node1's canonical block0→120.
- The gate is "correct" by its own logic (an EX-held current-tenure inode IS this node's authoritative work) — BUT node2's EXTENT MAP is a STALE PRIOR INCARNATION (block0→112 from a pre-rm-rf round) that node2 never reconciled to node1's fresh incarnation (block0→120). node2 holds EX legitimately yet has a structurally-stale fork.

### THEREFORE the fix is the RELOAD, not the merge:
node1 rm-rf's + mkdir's the dir EACH round → NEW incarnation, block0 freshly allocated @ fsb=15 (daddr 120). node2's cached VFS inode for ino=131 persists across the reuse with the PRIOR incarnation's fork (block0→112). node2's reload-on-EX-acquire MUST detect the incarnation change (on-disk di_gen != in-core i_generation → sess33 guard falls through, full xfs_idestroy_fork+from_disk rebuild) and adopt node1's block0→120. It FAILS to, because either: (a) the bounded down_write_trylock bail (xfs_mxfs_dlm.c:6717) skips the rebuild under create contention, or (b) node2 reads its OWN self-stale on-disk image (disk oscillates 112↔120 as each node's inode flush wins last), or (c) node2 fast-path-acquires without reloading.

### FIX (next session, in priority):
1. **Make node2's reload reliably adopt node1's fresh incarnation.** Within a CLEAN round node2 should reload to 120 (node1 wrote it fresh); the failure is node2's prior-incarnation fork surviving. Ensure: on EX acquire of a reused dir inode (gen-mismatch), the reload does NOT bail (block or restart, not silent-keep-stale @ 6717), and is NOT skipped on the fast path.
2. **Stop the disk oscillation**: node2 must never WRITE block0→112. Once node2's fork is reliably 120, it writes 120, disk stays 120, reloads give 120. Self-correcting once the reload is fixed.
3. If reload can't be made reliable, EXTEND the merge authority gate: even for an EX-held dir slot, if its block0 fsb DIFFERS from the durable on-disk image AND the on-disk image is a valid newer dir (peer's fresh incarnation), OVERLAY it (don't trust a structurally-divergent EX-held fork). Risky (the di_lsn-not-comparable problem); the reload fix is cleaner.

Build AFE4E833 (P-GROW0 + P-DIRIFLUSH detectors, gated). Marker NOT written. [[sess-tcp-FENCE-correct-location-iflush-cluster-not-iflush]] [[sess-tcp-FINDING-stale-iflush-is-under-EX-not-NL]] [[sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr]]
