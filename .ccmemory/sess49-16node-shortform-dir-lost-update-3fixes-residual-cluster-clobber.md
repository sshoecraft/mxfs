---
name: sess49-16node-shortform-dir-lost-update-3fixes-residual-cluster-clobber
description: sess49 (ccloop 14d31183): 3 PROVEN fixes for 16-node cross_write_read dirent loss (folio deadlock + SF self-skip + proactive file-create durability);…
metadata:
  type: project
---

# sess49 — 16-node shortform-dir durable dirent loss: 3 fixes + residual

Gate context: cache_coherency 4/4 PASSES (sess128 build). Remaining ship blocker is
the **16-node** criteria (posix_semantics --nodes 16, scaling_curve --nodes 16). The
`cluster` phase wedged/failed on `test_cross_write_read`: 16 nodes each create a file
in ONE shared shortform parent dir → one node's dirent durably lost. `concurrent_mkdir`
PASSES at 16 (mkdir hit the proactive flush; file-create did not — that was the gap).

Build progression this session (all KEEP, each reduced the failure):
- `C63A349` (sess48 start) → folio deadlock fix → `2E28291` → SF self-skip fix → `D8ADC3D`
  → proactive file-create durability → **`ABD1F70849A484A3CBBC609`** (current, on all 16 nodes).

## FIX 1 (folio self-deadlock) — xfs/xfs_mxfs_dlm.c ~L4864, mxfs_dlm_reload_inode S_ISREG
node14 md5sum hung 122s in `folio_wait_bit_common` under `invalidate_inode_pages2_range`.
Chain: xfs_file_buffered_read → iomap_readahead → read_pages (holds folios LOCKED) →
xfs_read_iomap_begin → xfs_ilock → mxfs_dlm_ilock_begin → reload → invalidate_inode_pages2
(blocking folio_lock on a folio THIS task holds) = self-deadlock when a peer EX BASTs us
mid-read after the top-of-read envelope ran. FIX: `invalidate_inode_pages2` →
`invalidate_mapping_pages(mapping,0,-1)` (non-blocking trylock, skips locked/dirty). This
UNBLOCKED the hang — cross_write_read now COMPLETES instead of wedging.

## FIX 2 (shortform-dir self-skip) — xfs/xfs_mxfs_dlm.c ~L3779, the sess36 P36-RELOAD-SELFSKIP
The self-skip (`if own log item in_ail||dirty||ili_fields||pin>0 → keep in-core, skip
reload`) wrongly fires for a SHORTFORM dir that RELEASED EX then re-acquired (peer modified
in between; ili_fields/pin are residue of our OWN earlier add, already drained). Proven:
disk had count=16 incl f_9, node kept stale in-core (no f_9), xfsaild flushed it → clobber.
FIX: exclude `S_ISDIR && if_format==XFS_DINODE_FMT_LOCAL` from the skip (kept for
extents/btree = sess36's real regression). For SF dirs the dinode is drained on EX release
(Invariant 1) so disk is authoritative on a stale reload.

## FIX 3 (proactive durability for FILE creates) — xfs/xfs_inode.c ~L1687
`mxfs_dlm_dir_inode_durable(dp)` (makes a shortform parent's dinode platter-durable) was
gated `du.ip && S_ISDIR(du.ip) && !dp->i_mxfs_self_created` — i.e. ONLY for mkdir children.
File creates into a shared shortform parent never flushed → last committer (never BAST'd)
loses its dirent (P127-DIRMISS sfcount=15 missing f_10). FIX: drop the `S_ISDIR(du.ip)`
requirement → `du.ip && !dp->i_mxfs_self_created`. Helper no-ops unless PARENT is SF dir;
the self-created gate still skips rsync's node-private parents (no rsync perf regression;
repro ran 12 rounds in 98s, NO CAW starvation). Dropped fail rate 80→16 obs, ~3/8 → ~1/14.

## RESIDUAL (NOT fixed) — co-resident inode-cluster stale-buffer clobber
~1/14 rounds still lose the GENUINELY-LAST committer (f_16, highest node). Disk ends with
f_1..f_15 (everyone except the last). PROVEN chain (repro_dirent_capture.sh round14, dir
ino=361 blkno=0x160):
1. nodeLast writes f_1..f_16 durable.
2. A co-resident node Z holds a STALE cached inode-cluster buffer for blkno 0x160 (dir 361's
   slot = f_1..f_15), KEPT by `P91-RELOAD-PROTECT` (mxfs_dlm_reload_inode ~L3847,
   `mxfs_buf_has_uncheckpointed_mods` true because a CO-RESIDENT inode in the same 4K cluster
   has this node's logged-not-checkpointed mods).
3. node Z's `xfs_iflush_cluster` writes the whole cluster buffer back; dir 361's slot is
   `P119-NONEX-FLUSH-SKIP`'d (xfs_inode.c ~L4144, i_dlm_mode!=EX) so it is NOT refreshed —
   the STALE cached f_1..f_15 is written → durably CLOBBERS f_16.
Root: shared inode cluster — different inodes modified by different nodes. P91 keeps the
whole stale buffer to protect a co-resident's mods; iflush_cluster then writes stale slots
for inodes we don't own. **In the repro, node1 creates ALL round/bar dirs so they pack into
shared clusters; in the real test the parent dir co-resides with sibling/barrier dirs that
ARE concurrently modified.** START NEXT SESSION at the comment xfs/xfs_inode.c:4303
("xfs_iflush_cluster ... writes the WHOLE cluster, carrying this node's STALE ...") — this
is the exact known surface. Candidate fix: before iflush_cluster writes a multi-node cluster
containing a P119-skipped (non-EX, peer-owned) slot, RE-READ that slot (or the cluster) from
disk so the writeback preserves the peer's current content; or make P91 refresh the specific
reloading slot instead of keeping the whole stale buffer. Likely needs care re: not losing
the co-resident's own in-core mods (iflush_cluster already copies dirty EX-owned inodes in).

## Repros (in tree, RULE 3)
- `tests/repro_dirent_loss.sh [N] [R]` — N nodes concurrent same-dir create, R rounds, reports loss rate.
- `tests/repro_dirent_capture.sh [N] [MAXR]` — runs until first loss, classifies coherency-vs-durable
  (drop_caches reappear?), dumps dir ino + P-SFDIR-RELOAD/P127-DIRMISS/P91/P119 dmesg from creator+observer.
Cheap 4-node `cross_write_read` PASSES; loss only at 16-way. Deploy = `bash tests/reset4.sh 16`
then set dirwr=1 + bind /mnt/mxfs-src on all 16. Detectors P127-DIRMISS, P91-RELOAD-PROTECT,
P119-NONEX-FLUSH-SKIP, P-SFDIR-RELOAD are all-on and decisive.

Related: [[sess84_lessons]] (same SF lost-update, last-committer CIL window) [[sess128-root-fix-phantom-ex-rearm-unpublished]] (4-node green).
