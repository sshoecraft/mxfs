---
name: sess64-face2-leftcontig-desync-leaf-lags-iext-by-one
description: sess64 Face-2 origin PROVEN: P64-LEFTCONTIG-DESYNC ino=131 iext=15 leaf=14 — in-core bmbt leaf lags iext by 1; LEFT_CONTIG merge in mkdir looks up le…
metadata:
  type: project
---

## sess64 Face-2 — the in-core bmbt leaf lags iext by ONE; both zsl faces share this root

Continues [[sess64-zsl-torn-dinode-leaf-never-14-incore-leaf-lags]]. Diagnostic build B9C27147
(= E6A40C95 leaf-rebuild KEEP + a probe at xfs_bmap.c:2800 BMAP_LEFT_CONTIG).

### DECISIVE Face-2 evidence (zsl64g, 16-node storm, ino=131 shared dir)
```
P64-LEFTCONTIG-DESYNC ino=131 iext=15 leaf_numrecs=14 broot_nrecs=1 old_off=39 old_sb=3407881 old_cnt=1 daddr=25047960 comm=mkdir
P64-LEFTCONTIG-DESYNC ino=131 iext=15 leaf_numrecs=14 broot_nrecs=1 old_off=39 old_sb=2097161 ... comm=mkdir
P64-LEFTCONTIG-DESYNC ino=131 iext=18 leaf_numrecs=17 broot_nrecs=1 old_off=40 old_sb=1310729 ... comm=mkdir
```
At the Face-2 shutdown (`Internal error i != 1 at xfs_bmap.c:2800, xfs_bmap_add_extent_hole_real`
→ xfs_trans_cancel:1060 → xfs_create): **in-core iext = N, bmbt leaf = N-1 (lags by exactly 1),
single leaf**. A mkdir doing a LEFT_CONTIG merge calls xfs_bmbt_lookup_eq(cur,&old,&i) to find the
left-neighbor `old` extent in the bmbt; the leaf is missing it (only N-1 recs) → i!=1 →
EFSCORRUPTED shutdown. (old_sb differs per occurrence = the stale left-neighbor; ties to
P55-DIRWRITE-OVER-INODE = stale in-core extent map.)

### UNIFIED ROOT (both zsl faces)
The in-core bmbt LEAF buffer lags the authoritative in-core iext tree by 1:
- Face A (di/leaf tear): at iflush, di_nextents=N published over leaf=N-1 → reloading peer trips
  ir.loaded(N-1)!=if_nextents(N) at xfs_bmap.c:1286. **FIXED at flush by E6A40C95 leaf-rebuild**
  (P64-LEAF-REBUILD fires, P59 152→5, silent 1600→171 in zsl64f).
- Face B (this): the SAME lag, but a btree op (LEFT_CONTIG merge / case-0 insert lookup) fails
  MID-TRANSACTION in mkdir, BEFORE any flush → flush-time rebuild can't help. 7 node shutdowns/run.

### WHY THE FLUSH FIX IS NECESSARY-BUT-INSUFFICIENT
E6A40C95 reconciles the leaf from iext only at iflush. Face B needs the in-core leaf consistent
DURING transactions. Variance is high (zsl64f silent=171, zsl64g silent=1600) depending on whether
Face B shuts nodes down early.

### NEXT — SOURCE FIX (fix the lag itself, not just at flush)
The leaf is the cursor's just-read buffer (xfs_btree_read_buf_block → cached buf at the leaf
daddr). iext=N is authoritative; leaf=N-1 means the cached leaf buffer is one image stale. Two
candidate origins still not separated (enhanced P63-INSERT-DESYNC pre/post in build, but it's RARE
— hasn't fired since zsl64c):
(a) a stale plain-bio READ DMA'd the older on-disk leaf over the in-core leaf (P61-BIO-OVER-LOGGED
    -BMBT guard at pal/linux/xfs_buf.c:3458 only catches leaves with UNCHECKPOINTED mods — gap:
    checkpointed-clean-but-not-yet-durable, or a window the guard misses);
(b) xfs_btree_insert grew iext but not the in-core leaf.
FIX OPTIONS:
1. Broaden the P61 guard: refuse ANY disk read of a bmbt leaf that has XBF_DONE (in-core image
   present) and is owned by an inode this node holds EX (in-core strictly authoritative — the
   xfs_buf.c:3436 comment already argues this). Safety relies on reload-evict clearing XBF_DONE so
   a genuine post-release reload still cold-reads. RISK: sess60 found evicting a loaded leaf
   reverts it — test carefully.
2. Reconcile-at-use: in xfs_bmap_add_extent_hole_real, when the lookup desync is detected
   (leaf_numrecs != iext, single leaf, extents loaded), rebuild the leaf from iext (same idiom as
   E6A40C95) and retry the lookup instead of shutting down. Mid-transaction leaf rewrite must be
   logged (xfs_trans_log_buf) — heavier but precise.

### STATE
Build at session end: B9C27147 (KEEP the E6A40C95 leaf-rebuild; the bmap.c:2800 probe is
diagnostic-only, harmless to keep). Criterion zsl STILL FAILS. Marker NOT written. Other 3 FAILs
(fence_during_write, rsync_paired, posix_multi16) untouched this session.
