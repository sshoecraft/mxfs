---
name: sess62-zsl-bmbt-leaf-write-never-submitted-confirmed
description: sess62: zsl root re-confirmed — bmbt leaf write for ino131 never reaches bio (P60-BMBTWRITE~0 cluster-wide); leaf goes XBF_DONE-clean w/o I/O so disk…
metadata:
  type: project
---

## sess62 (ccloop 14d31183) — zero_silent_loss: leaf-write-never-submitted CONFIRMED

Builds on [[sess61-zsl-root-di-ahead-of-bmbt-leaf-ordering]] and
[[sess60-zsl-bmbt-leaf-write-essentially-never-submitted]]. Criterion STILL FAILS.
Marker NOT written. Current build **B548E404**.

### total_fs_silent is VARIANCE-DOMINATED — do NOT use it to judge fixes
3 runs same-ish code: 1600 → 375 → 1600. The count = cascade blast radius of
whichever node shuts down first, NOT a fix metric. MUST measure per-SIGNATURE
shutdown counts instead (grep dmesg), not the RESULT line.

### Three shutdown signatures, ALL on shared storm dir ino=131, all one root
1. **SIG1** `ir.loaded != if_nextents` xfs_bmap.c:1286 (xfs_iread_extents) — DOMINANT.
   P59-IREAD-MISMATCH: loaded=16 if_nextents=17 broot_lvl=1 (delta 1, sometimes 3).
2. **SIG2** `!(flags & XFS_DABUF_MAP_HOLE_OK)` xfs_da_btree.c:2814 (xfs_dabuf_map bno 2):
   `br_startoff 2 br_startblock -2(HOLE)` — leaf references a dir block the extent
   map doesn't map.
3. **SIG3** `i != 1` xfs_bmap.c:2800 xfs_bmap_add_extent_hole_real BMAP_LEFT_CONTIG:
   xfs_bmbt_lookup_eq can't find the in-core left extent in the bmbt (iext ahead of bmbt).
All three = di_nextents (=if_nextents) is ahead of the on-disk bmbt leaf record count.

### DECISIVE NEW PROOF (build B548E404, this session)
- **Reload bmbt-eviction fix did NOT remove SIG1** (still 20× cluster-wide, sole sig).
  Evicting the cached leaf forces xfs_iread_extents to COLD-READ disk; the mismatch
  surviving PROVES the skew is GENUINELY ON-DISK (di=17/leaf=16 on the platter), NOT a
  reader stale-cache artifact. Reader-side fixes cannot help.
- **P60-BMBTWRITE owner=131 fired only 2× CLUSTER-WIDE** (test3 numrecs=14, test10=16);
  most nodes totalany=0. => ino=131's bmbt leaf WRITE essentially never reaches
  xfs_buf_submit_bio. Confirms sess60.
- **P61-BMBTSCAN at release/iflush: leafrecs==if_nextents, cand=0 wrote=0** on most nodes
  = the in-core leaf buffer is CLEAN (XBF_DONE) with N records and CLAIMS durable, yet
  disk has N-1. => the leaf BLI left the AIL / buffer marked XBF_DONE-clean WITHOUT a bio
  ever firing. The dirty leaf's logged change is being discarded (stale/abort/ail_delete
  path) or the buffer is marked done without I/O. THIS is the mechanism to pin next.

### REFUTED this session (RULE 4, do NOT retry)
- **P62-RELOAD-FORK-SHRINK** hypothesis (reload shrinks in-core fork below own dirty
  leaf): shrink=1 fired **0×**. Reload state is CONSISTENT (incore_nx==disk_nx, in_ail=0,
  pin=0). Probe KEPT (always-on, harmless) at xfs_mxfs_dlm.c before xfs_idestroy_fork.
- **Reader-side stale-leaf-on-reload** (added mxfs_dir_evict_bmbt_blocks inside reload):
  did NOT fix SIG1 (skew is on-disk). The evict is still CORRECT/defensive — KEEP — but
  not the fix.

### Code changes landed (build B548E404) — re-evaluate next session
1. **xfs_iflush leaf-ordering fix** (mxfs_iflush_force_bmbt_durable in xfs_mxfs_dlm.c,
   called from xfs_iflush before xfs_inode_to_disk): flushes BTREE data-fork bmbt leaves
   before the dinode under ILOCK. Intent good but INEFFECTIVE because the leaf is
   ALREADY clean (cand=0) at iflush — there's nothing to flush; the write was lost
   earlier. Possibly neutral. Reconsider/keep.
2. **Reload bmbt-evict** (mxfs_dir_evict_bmbt_blocks call inside mxfs_dlm_reload_inode,
   ~L5152, for S_ISDIR): KEEP (correct, proved skew is on-disk).
3. Probes KEEP: P62-RELOAD-FORK-SHRINK, P62-IFLUSH-BMBT-ORDER (instr-gated).

### NEXT (RULE 4) — pin WHY the dirty bmbt leaf leaves AIL without a bio
The leaf becomes XBF_DONE-clean (claims durable) but disk lags + bio never fires.
Candidates: (a) the freshly-allocated bmbt leaf buffer sits on pag_mxfs_alloc_buflist
with _XBF_DELWRI_Q set (the CLAUDE.md "_XBF_DELWRI_Q collision" design tension) so
xfsaild's xfs_buf_delwri_queue returns false → XFS_ITEM_FLUSHING forever, and the
Phase-2 drain does NOT cover bmbt leaves → never written; (b) a stale/invalidate path
xfs_trans_ail_delete's the dirty leaf BLI without writing. Probe: instrument the leaf
BLI lifecycle — at xfs_buf_item_push / xfs_buf_delwri_queue return-false for a
bmbt-ops buffer owned by 131, and at xfs_buf_stale/ail_delete of a dirty bmbt leaf —
log owner, numrecs, flags (_XBF_DELWRI_Q, _XBF_MXFS_ALLOC_QUEUED), in_ail. If (a):
ensure the Phase-2 drain (drain_alloc_buflist) or release drain actually bwrites
bmbt-ops buffers, OR clear the alloc-buflist DELWRI collision for bmbt leaves so
xfsaild can queue+submit them.

### INFRA
Storm re-wedges most nodes. `virsh -c qemu:///system destroy+start` ALL 16, sleep 40,
verify "nodes up 16/16". Criterion: ./tests/criteria/zero_silent_loss.sh --iters 1
--dpn 100 --mode 1 (nohup, poll ~480s). P59-IREAD-MISMATCH + P60-BMBTWRITE +
P61-BMBTSCAN are always-on (not instr-gated) — grep them for per-signature truth.
