---
name: sess64-zsl-torn-dinode-leaf-never-14-incore-leaf-lags
description: sess64: zsl PROVEN FIX (E6A40C95, KEEP) — rebuild single-leaf bmbt from authoritative iext at iflush before di_nextents publish; silent 1600→171, P59…
metadata:
  type: project
---

## sess64 (ccloop 14d31183) — zero_silent_loss: leaf-rebuild fix PROVEN, two residual faces

Criterion STILL FAILS (total_fs_silent 1600→**171**, threshold=0). Marker NOT written.
**KEEP build E6A40C95** (the leaf-rebuild fix below — proven big win).

### ROOT (pinned, sess59→64): in-core bmbt LEAF lags authoritative in-core iext tree
The single shared storm dir (ino=131) grows fast across 16 nodes. Its in-core bmbt LEAF buffer
falls behind the in-core iext tree / if_nextents (P63-INSERT-DESYNC: leaf bb_numrecs trails
if_nextents right after xfs_btree_insert — RARE/intermittent; or a post-insert stale plain-bio
read DMAs the older on-disk leaf over a checkpointed-clean buffer). At flush the inode-cluster
write publishes di_nextents=N while the bmbt leaf is N-1 → on-disk torn pair → a reloading peer
trips `ir.loaded(N-1) != if_nextents(N)` at xfs_bmap.c:1286 (xfs_iread_extents) → EFSCORRUPTED →
"Structure needs cleaning" cascade. PROVEN: no P63-LEAFWR ever shows numrecs=N (leaf never
durably reaches N); P60-RELAUDIT "INCONSISTENT-AT-RELEASE di_nextents=N iext=0 need_iread=1
leafsum=N-1". sess55 confirms the related P55 face is STALE BMAP, not allocator double-alloc.

### THE FIX (E6A40C95, KEEP) — mxfs_iflush_force_bmbt_durable (xfs/xfs_mxfs_dlm.c ~389)
Called from xfs_iflush (xfs/xfs_inode.c:4219) with ILOCK held, immediately BEFORE di_nextents is
copied to the on-disk dinode → iext tree frozen & authoritative. In the destage loop, for the
SINGLE-LEAF case (broot_nrecs==1, level-0 leaf, extents loaded, leaf numrecs != if_nextents,
if_nextents <= mp->m_bmap_dmxr[0]): re-serialize the leaf's records straight from the iext list
(for_each_xfs_iext → xfs_bmbt_disk_set_all into xfs_bmbt_rec_addr(mp,lblk,1+cnt)), set
lblk->bb_numrecs = cpu_to_be16(cnt). Mirrors xfs_bmap_extents_to_btree leaf-fill. Then the
existing xfs_bwrite destages the now-consistent leaf, CRC recomputed by write verifier.
Log: P64-LEAF-REBUILD (fired: ino=131 old_numrecs=18 new=19 if_nextents=19).
RESULT: total_fs_silent 1600→171; P59-IREAD-MISMATCH 152→5; the dominant di/leaf-tear shutdown
nearly eliminated. NOTE: xfs_btree_set_numrecs is STATIC (not visible) — set bb_numrecs directly.

### RESIDUAL (next targets, both trace to the SAME in-core desync the fix only patches at flush)
1. **nheld=0 torn path**: P63-TORN-FLUSH ino=131 if_nextents=17 leafsum=0 nheld=0 — the bmbt leaf
   buffer is NOT cached at iflush, so the rebuild loop finds nothing → di=17 still published over
   a stale on-disk leaf. Fix idea: when broot_nrecs==1 & extents loaded but leaf not cached, read
   the leaf daddr from if_broot ptr, fill from iext, write — but BEWARE sess44 deadlock (no
   blocking read in submit/AIL context). ~5 residual P59 reader-shutdowns come from this window.
2. **Face 2 (now dominant): stale in-core extent MAP** → `Internal error i != 1 at xfs_bmap.c:2800,
   Caller xfs_bmap_add_extent_hole_real` → xfs_trans_cancel:1060 → xfs_create shutdown (7 nodes
   this run). The desynced in-core iext/bmbt makes xfs_bmbt_lookup_eq return wrong i during a NEW
   extent insert. Plus P55-DIRWRITE-OVER-INODE (13×): dir extent records point at live inode
   clusters (mode 040755) — stale bmap. To kill Face 2 the in-core leaf-vs-iext desync must be
   fixed AT SOURCE (prevent the revert / the dropped btree insert), not just at flush.

### SOURCE-FIX DIRECTION (for the desync itself)
The P61-BIO-OVER-LOGGED-BMBT guard (pal/linux/xfs_buf.c:3458) refuses a disk read over a bmbt leaf
ONLY when mxfs_buf_has_uncheckpointed_mods(bp). GAP: a CHECKPOINTED-clean leaf whose on-disk image
hasn't landed yet still gets reverted by a re-read. Candidate: broaden the guard to refuse ANY
disk read of a bmbt leaf that has XBF_DONE (in-core image present) AND is owned by an inode this
node holds EX (in-core strictly authoritative — comment at xfs_buf.c:3436 already argues this).
RISK: must still allow the cold-read after a fresh reload (need_iread / XBF_DONE cleared). Test
carefully — sess60 found evicting a loaded leaf reverts it.

### INFRA REMINDERS (cost real cycles this session)
Full virsh reset ALL 16 SEQUENTIALLY before EVERY run (a backgrounded destroy loop exited 144
mid-way, left stale mxfs mounts whose umount wedges D-state on SCSI reservation conflict →
"teardown testN FAILED"). Verify uptime~0 & /proc/modules mxfs=0 before running. SSH:
tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass "<cmd>" (passFILE path). zsl insmods
/src/mxfs/mxfs.ko via NFS automatically (no scp). Judge by per-signature dmesg, not RESULT line.

Links: [[sess63-zsl-bmbt-fua-fix-eio-gone-but-incore-leaf-reverts]]
[[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]] [[sess55-faceB-is-M2-stale-bmap-not-allocator]]
