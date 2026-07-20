---
name: sess54-dir-coherency-and-bnobt-dblalloc-faces
description: sess54 (ccloop 14d31183): posix_multi16 >600s = MULTIPLE distinct shutdown faces under 16-node shared-dir storm. Fixed stale-extent-map face (3 chang…
metadata:
  type: project
---

# sess54 (ccloop 14d31183) — posix_semantics_multi16 is the ONLY failing criterion

`.criteria_results.json`: 18/19 PASS; sole FAIL = `posix_semantics_multi16` (elapsed>600s).
The `p` prompt file is STALE (says cache_coherency — that PASSes now). Root of the
600s timeout = FS **shutdowns** under the 16-node concurrent shared-dir workload (each
shutdown → every test barrier hangs 120s → budget blown). posix_semantics.sh --nodes 16
runs tests/cluster/*.sh; e.g. dir_stress has all 16 nodes creating subdirs in ONE shared
parent — same contention as the reproducer.

## Fast reproducer (KEEP)
`tests/repro_agi_unlink_storm.sh 16 6` — 16 nodes create+delete 40 dirs×8 files each
across 4 shared parents (inodes 132-136), N rounds. Hits a shutdown in round 1-3.
Requires cluster mounted (`tests/reset4.sh 16` first). HIGH VARIANCE: different runs hit
different faces. Build current head: deploy via `make modules` (nodes NFS-load /src/mxfs/mxfs.ko).

## THERE ARE ≥2 INDEPENDENT SHUTDOWN FACES (criterion needs ALL fixed → 0 shutdowns)

### Face A — STALE DIR EXTENT MAP (FIXED this session, 3 changes, KEEP)
Symptom: `Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at xfs_da_btree.c:2814`,
`xfs_dabuf_map: bno 8388608 inode 133` (bno 0x800000 = dir2 LEAF offset), or
`xfs_dir3_block_verify block 0xNNNN`. Cause: a peer GROWS a shared dir
(shortform→block→leaf) or shrinks+regrows onto a different block; the peer's
DIR_MODIFY evict-ring event only refreshed DATA blocks (i_dlm_dir_gen) and only
armed MXFS_IF_DIR_RELOAD for LOCAL dirs. Block/leaf dirs kept a STALE extent fork →
xfs_bmapi_read maps a dir offset to a HOLE / freed block → shutdown.
**FIXES (all in tree):**
1. `xfs/xfs_mxfs_dlm.c` mxfs_dlm_evict_inode_cb (~8564): arm MXFS_IF_DIR_RELOAD for
   EVERY dir format, not just LOCAL. Log now `EVICT-RING-DIRMOD ... fmt=N reload=1`.
2. `xfs/xfs_mxfs_dlm.c` mxfs_dlm_dir_consumer_refresh (~1177): consume
   MXFS_IF_DIR_RELOAD on the LOOKUP path (xfs_lookup calls it) via
   mxfs_dlm_reload_inode (rebuilds extent fork: xfs_idestroy_fork+xfs_inode_from_disk).
   readdir already did this.
3. `xfs/xfs_mxfs_dlm.c` ilock_begin fast-path dir_ex_stale_refresh branch (~5487):
   the slow-path acquire reloads (line ~5847) but the FAST-path stale_base re-grant only
   did mxfs_dir_drain_evict_data_blocks (data blocks, NOT extent map). Added
   mxfs_dlm_reload_inode there too. (reload uses down_write_trylock; no ILOCK held at
   ilock_begin — safe, mirrors slow path.)
VERIFIED firing: `EVICT-RING-DIRMOD ino=133 fmt=2 reload=1`. Pushed reproducer from
round-1 shutdown → round-3 in one run. NOT sufficient alone (Face B remains).

### Face B — bnobt DOUBLE-ALLOCATION (THE deep blocker, UNFIXED)
Symptom: `DLM inode reload imap_to_bp failed: ino=134 rc=-5` (EIO) — a LIVE shared-parent
inode's cluster is unreadable; a dir-data block was allocated OVER ino 134's live inode
cluster → cluster fails its verifier. Present in the ORIGINAL build 9C3D67D7 too
(round-1 `imap_to_bp ino=128` on test13, before any sess54 change). Mechanism: a node
allocating a dir-data block had a bnobt view showing a block free that actually holds a
live inode chunk → cross-node AG free-space (bnobt) incoherency. This is the
sess24/39/42/44/47/81/90/121 AG double-alloc family. Existing detectors (P88/P117/P-DEXT/
DBLALLOC) did NOT fire (or were drowned by EVICT-RING spam). ikeep (below) did NOT fix it.

### ikeep attempt (inode-chunk-keep) — applied, did NOT fix, KEPT (low-risk, real class)
`xfs/libxfs/xfs_ialloc.c` xfs_difree_inobt (~2442) + xfs_difree_finobt (~2613): in
multi-node mode, never delete a fully-free inode chunk (gate the removal branch on
`!(m_mxfs_dlm && !single_node)`) so inode-cluster blocks never re-enter the AG free pool.
Targets sess53's durable inode-cluster-aliasing. Shutdown PERSISTED (Face B is at
chunk-ALLOC bnobt staleness, not chunk-free), so ikeep alone is insufficient. Kept because
it eliminates a proven durable-corruption class at low risk; revisit if it causes inode-
space pressure.

## Diagnostics added (KEEP, ungated+ratelimited)
- `xfs/libxfs/xfs_da_btree.c` after the sess39 torn-read retry loop (~3260):
  `P54-DIRBLK-PROBE` — on retry-exhausted dir-block EFSBADCRC/EFSCORRUPTED, plain-reads
  the disk daddr and reports magic_ok/owner_ok(==reading dir)/disk_crc_ok. Disambiguates
  cache-torn vs durable vs extent-map-aliasing. (Did not fire this session — failures were
  DABUF-HOLE/inode-cluster, not the data-fork CRC path.)

## NEXT (RULE 4): fix Face B (bnobt double-alloc). The dir-data allocator picks a block
inside a live inode chunk. Add a detector at data-extent allocation (xfs_bmap_btalloc /
xfs_alloc_vextent result) that checks the allocated agbno range against the inobt
(live inode chunk overlap) — catch the double-alloc AT THE SOURCE and dump the AG's
bnobt/agf freshness (mxfs_ag_buf_disk_differs) to prove stale-read vs durable bnobt
corruption. Then fix the AG-meta coherency hole at chunk-ALLOC time (acquire-side cold
read of bnobt/inobt for the alloc AG, or the sess90 uncheckpointed-mods guard extended to
alloc btrees). The EVICT-RING-DIRMOD spam (gen races to 200+/dir in seconds) floods dmesg
and is a perf concern — consider rate-limiting harder or a non-thundering-herd dir-coherency
scheme for heavy shared-dir contention. Related: [[sess24-PROVEN-inobt-incoherent-at-alloc]],
[[sess121-dir-block-lost-update-next]], [[sess90_lessons]]. Marker NOT written.
