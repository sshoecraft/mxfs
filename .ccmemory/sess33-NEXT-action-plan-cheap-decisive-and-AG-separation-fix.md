---
name: sess33-NEXT-action-plan-cheap-decisive-and-AG-separation-fix
description: sess33 NEXT action plan for dir_reuse 2/tcp: (1) chk_mxfs after a corrupting run = zero-cost decisive M1 (on-disk double-alloc) test; (2) structural…
metadata:
  type: project
---

## sess33 — NEXT-SESSION ACTION PLAN (dir_reuse_coherency 2/tcp)

Root is PROVEN data-over-inode-cluster / cross-node block coherency under reuse — see
[[sess33-PROVEN-ROOT-inode-data-block-double-alloc]]. Per-alloc disk probes TIME OUT the test (RULE 0).
Two highest-value moves that AVOID that trap:

### MOVE 1 (zero hot-path cost): chk_mxfs after a corrupting run = decisive M1 test
The kernel probe approach failed because reading disk per-allocation is too slow. Instead, let the test
CORRUPT (run it a few times until a node logs `xfs_inode_buf_verify`/`Shutting down` — happens ~1/3
runs), then inspect the FROZEN on-disk image with the USERSPACE fsck (no hot-path cost):
```
# after a node shuts down (FS frozen, corruption on disk):
tools/chk_mxfs -v /dev/sda    # on the shut-down node (or copy the LUN)
```
If chk_mxfs reports a block owned by BOTH an inode chunk (inobt) and a file/dir extent (bnobt/bmap
disagreement / double-allocated block) → **M1 cross-node allocator double-alloc CONFIRMED** → fix AG
free-space coherency (the inode-CHUNK alloc path's bnobt update must be durable + visible before the
peer's data alloc; verify mxfs_dlm_ag_drain_meta_buffers actually runs for the RECLAIM/evict release
path mxfs_dlm_evict, and that the inode-chunk alloc takes the same AG-DLM path as data alloc).
If chk_mxfs shows the bnobt/inobt CONSISTENT (no double-alloc) but a file extent points into an inode
chunk → **M2 stale file/dir extent-map** → fix the dir/file reload coherency.
NOTE: daddr known from the dmesg (xfs_inode_buf_verify "block 0xNNN"); also `P26-IGET-FAIL inum=` ==
that block. May need to umount/`rmmod` (or virsh-reboot) the shut-down node before chk_mxfs if the
device is busy; the on-disk corruption persists across the reboot.

### MOVE 2 (structural fix — kills the contention, addresses ALL faces): per-node AG affinity for
SHARED-dir file allocations.
ROOT enabler: the test's files get inodes+data in the SHARED DIR's AG (XFS locality), so BOTH nodes
hammer the SAME AG concurrently — AG-affinity (preferred_ag = slot%agcount) is DEFEATED for shared-dir
children. If each node allocated its OWN children's inodes AND data from its OWN preferred AG instead
of the dir's AG, the two nodes would never contend on one AG's free-space → no cross-node double-alloc,
no stale-AG-meta races. Implement by overriding the inode/bmap allocation target (xfs_dialloc /
xfs_bmap_btalloc start-AG) for a node when the parent dir is SHARED (multi-node, !self_created): use
mxfs node-slot preferred AG, not XFS_INO_TO_AGNO(parent). Risk: changes allocation layout; verify it
doesn't break single-node / other tests and respects ENOSPC fallback. This is the most likely path to
actually CONVERGE the criterion (vs the per-buffer coherency patches sessions have layered for 30+
sessions without converging).

### VARIANCE WARNING: every run shows a DIFFERENT face (data-over-inode-cluster shutdown / dir3_block_
verify 0x78 shutdown / lookup_fail stale-leaf / readdir-short 181/200 data-loss / hang no-result). Run
the SAME build 3-5× before concluding a fix worked or a theory is refuted. tests/reset2.sh before EVERY
run (D-state unmount wedge; hangs leave the cluster wedged).

### Tree state: CLEAN/BUILDABLE DBD3A375. P33 probes (log-only) left in xfs_dir2_leaf.c / xfs_inode_buf.c;
P33-DIRGROW-REVERT-SKIP (xfs_mxfs_dlm.c) is a NO-OP (fires 0×) — safe to revert. alloc.c probe reverted.
[[sess33-PROVEN-ROOT-inode-data-block-double-alloc]] [[sess30-FACEC-bnobt-double-alloc-deep-dive]] [[sess55-faceB-is-M2-stale-bmap-not-allocator]]
</body>
