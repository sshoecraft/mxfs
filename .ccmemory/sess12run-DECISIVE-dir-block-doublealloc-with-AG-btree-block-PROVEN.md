---
name: sess12run-DECISIVE-dir-block-doublealloc-with-AG-btree-block-PROVEN
description: sess12(ccloop) PROVEN by raw-disk: dir_reuse loss = dir data block daddr double-allocated with an AG btree block (bnobt/cntbt). Root = AG free-space…
metadata:
  type: project
---

## sess12 (ccloop) DECISIVE raw-disk proof — dir_reuse loss is AG free-space DOUBLE-ALLOCATION

### Repro (clean build F0D7B279, dirwr=2): `tests/tcp/drc4_capture.sh 24` → FAIL round 4 ino=131
9 entries durably lost on ALL 4 nodes, LOOKUP_ENOENT + REREAD_MISS: node1_f5/f11/f18/f21/f34 (data) + node2_f35/f42/f44/f46 .md5. These 9 live in ONE dir data block.

### The smoking gun
P-RELFLUSH on test1 dumps the dir's data block `daddr=27211984` as `names=[magic=0x0]` (in-core: zeroed dir magic) at every release. RAW DISK READ of that physical block (offset = (daddr + xfs_data_offset/512)*512; xfs_data_offset=100704256 from chk_mxfs) shows a **v5 XFS AG-rooted (short) btree block**, NOT a dir block:
- offset 0x10 blkno field = 0x019f38d0 = **27211984** (self-id matches the daddr)
- offset 0x20 uuid = `da513779-8f75-43f0-a3cd-187268c40d84` = **the FS UUID** (chk_mxfs)
- body = repeating 4-byte btree records ("..VJL")
- magic@0x00 = 0x00000000 (zeroed — clobbered header)
Header layout (uuid@0x20, owner@0x30, crc@0x34) = `xfs_btree_block` SHORT form = bnobt/cntbt/inobt/finobt.

### CONCLUSION (RULE 4 PROVEN)
`daddr=27211984` is DOUBLE-ALLOCATED: it is an AG free-space/inode **btree block** AND the dir's data block. The bnobt said this block was FREE when it was actually an in-use btree block → the dir-grow allocator (xfs_bmap_btalloc→xfs_alloc) handed it to the dir → the 9 entries were written to it in-core but the on-disk image is the btree block → durable loss. This is the SAME root as the `fence_during_write` / `tcp_dlm_scaling` **"Corruption of in-memory data (0x8)" at xfs_defer_finish_noroll/xfs_trans_cancel** shutdowns (extent alloc/free deferred-op corruption). ONE root unifies all real 4/tcp failures.

### ROOT LAYER = cross-node AG free-space metadata (AGF/bnobt/cntbt/inobt) incoherency
The dir is serialized by dir DLM EX, but the underlying AG block allocation is serialized only by AG-DLM. A node allocating from an AG with a STALE in-core bnobt/cntbt (peer already allocated the block but this node's cached btree buffer wasn't invalidated on AG-DLM acquire, or peer's update wasn't drained on release) double-allocates. Same family as sess24/42-47/79-90 bnobt double-free/alloc.

### NEXT (RULE 4)
Audit AG-DLM acquire invalidation: does mxfs invalidate ALL cached AG-meta buffers — AGF, AGI, AND the bnobt/cntbt/inobt/finobt **btree BLOCKS** (not just the AGF/AGI headers) — on AG-DLM acquire so the next read FUA/coherent-refetches the peer's durable free-space tree? And does AG-DLM release drain all those btree-block writes before unlock? Suspect the btree BLOCKS under the AGF are not invalidated/drained, only the AGF/AGI roots. fua_disable=1 currently (plain-bio to SCST coherent cache); sess122 made the plain-bio AG-meta read-over-logged interlock LOG-ONLY.

Cluster left mounted after drc4_capture (exit 0 on first fail). Reset: virsh destroy+start test1-4. See [[sess12run-CLEAN-BUILD-4tcp-baseline-two-real-bugs]] [[sess90_lessons]].
</body>
