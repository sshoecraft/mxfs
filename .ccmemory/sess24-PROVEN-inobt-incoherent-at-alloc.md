---
name: sess24-PROVEN-inobt-incoherent-at-alloc
description: sess24(ccloop): RULE-4 PROVEN root of inode double-alloc/type-flip — allocator carves inodes the COHERENT disk shows already LIVE (mode 040755). Dete…
metadata:
  type: project
---

# sess24 (ccloop 4eef1f39, 2026-06-07) — ROOT PROVEN (RULE 4), build 1F7AF33C

## THE PROOF (decisive, reproducible)
Added detector **P-IALLOC-DBLALLOC** (gated `mxfs.dbg_ialloc_dblcheck=1`, default 0):
in `xfs_dialloc_try_ag` (xfs/libxfs/xfs_ialloc.c ~2017, right after `xfs_dialloc_ag`
carves `ino`), read the carved inode's mode from the COHERENT cluster view (plain
bio = mxfs_dbg_disk_di_mode_coherent in xfs_mxfs_dlm.c). If mode != 0 → a peer/prior
durable owner already holds that inode number = the inobt we read was STALE.

Ran `test_cross_visibility` ISOLATED on a clean reset4 cluster (build 1F7AF33C, all 4
nodes, dblcheck=1). Test PASSED but the detector FIRED on 3 nodes:
```
test2: P-IALLOC-DBLALLOC ino=4194432 agno=2 coherent-disk mode=040755 gen=2326740076 LIVE
test3: P-IALLOC-DBLALLOC ino=6291584 agno=3 coherent-disk mode=040755 gen=2027475174 LIVE
test4: P-IALLOC-DBLALLOC ino=2097280 agno=1 coherent-disk mode=040755 gen=1528251987 LIVE
```
All carved inodes are DIRECTORIES (mode 040755) that the durable SCST disk shows LIVE.
So the allocator carves an inode that is durably a live directory ⇒ **the inobt
free-space view is incoherent with the durable inode-cluster dinode at the allocation
boundary.** This is the long-sought root of RELOAD-TYPEFLIP-STALE-SKIP (incore dir vs
disk regfile) + `inobt record corruption AG N` + xfs_difree_inobt -117 SHUTDOWN. The
criterion's full-run 0/4 cascade starts here. (SESS50-STARVE also fires 4-7×/node — a
SEPARATE timing blocker.)

## WHICH inconsistency (two non-exclusive sub-mechanisms, both real bugs)
1. STALE INOBT on this node: a peer modified the AG and our cached inobt wasn't
   cold-read (acquire coldread_discard hole, or nested-hold never re-read).
2. UNDRAINED INODE-CLUSTER on FREE (Gemini W2 / sess102 Gap-c): when an inode is
   FREED, di_mode is set 0 in its xfs_inode_buf_ops CLUSTER buffer, but that buffer is
   NOT in the AG BAST drain set (`mxfs_dlm_ag_drain_meta_buffers` filter ~7336 covers
   only AGF/AGFL/AGI/bnobt/cntbt/inobt/finobt). So the inobt-free can reach the SCST
   disk while the dinode di_mode=0 does NOT → peer reads inobt=free + dinode=live(dir).
   (XFS clears di_mode on ifree, so coherent mode=040755 means the free's dinode write
   was NOT durable, OR the inode is genuinely still live = concurrent-mkdir orphan.)

Workload that triggers it: 4 nodes race `mkdir -p .mxfs_test/<sub>` (same name) — each
allocates a candidate dir inode in its OWN AG (affinity); losers get EEXIST and free
their candidate; the free's dinode-clear isn't durable before the AG/inobt releases →
re-carve sees inobt-free but dinode-live.

## NEXT STEP (RULE 4 step 2b — patch the proven cause)
Primary candidate fix = **W2 release-side**: add `xfs_inode_buf_ops` to the AG BAST
drain set so a freed/allocated inode's CLUSTER dinode is platter-durable BEFORE the AG
(and its inobt) is released. Additive, scoped, drains only dirty/in_ail cluster bufs
via the existing xfs_bwrite path. Then re-run cross_visibility with dblcheck=1 and
confirm P-IALLOC-DBLALLOC count drops to 0. If it persists → sub-mechanism 1 (stale
inobt read); next is acquire-side: force inobt/finobt/AGI cold-read for the alloc AG.
KEEP the P-IALLOC-DBLALLOC detector (gated off) — it's the definitive regression gate.

## METHODOLOGY NOTES
- Module wouldn't rmmod after a killed run ("File exists" on insmod) → power-cycle ALL
  4 (LIBVIRT_DEFAULT_URI=qemu:///system sudo virsh destroy+start; wait 90s NFS) then
  reset4. Enable detector: `echo 1 > /sys/module/mxfs/parameters/dbg_ialloc_dblcheck`
  on every node after mount, then dmesg -C, then run the test.
- cross_visibility / cross_write_read PASS in ISOLATION; full criterion is high-variance
  (the double-alloc fires even on a passing isolated run — it's just not always fatal).
Marker NOT written.
</body>
