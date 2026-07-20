---
name: sess49b-BREAKTHROUGH-torn-disk-reload-gate-partial-8tcp
description: sess49b(ccloop): 8/tcp root=durable dir map GAP born at xfs_dir2_shrink_inode MIDDLE-block free. Reload-gate=partial fix (1/3 PASS, oops+cascade gone…
metadata:
  type: project
---

## sess49b (ccloop) — 8/tcp dir_reuse: root precisely localized, partial fix landed

### Build A9180EB2 (KEEP). Progress: deterministic 0/8 cascade-shutdown → 1/3 PASS, NO oops, NO full shutdown.
2/4 tcp still PASS; 1/tcp N/A (MINNODES=2). 8/tcp NOT yet 100% — marker NOT written.

### PROVEN ROOT (RULE 4, decisive)
The 8/tcp DABUF_MAP_HOLE shutdown = a durable on-disk dir dinode (ino 131) whose data-fork EXTENTS map has a GAP — a missing data block the leaf still references. Confirmed DISK-TORN via FUA probe (`P-HOLE-DISK DISK_MAPS_WANT=0`, disk extents e.g. [off0, off4, leaf], di_size=20480 → blocks 1,2,3 absent).

### WHERE THE GAP IS BORN (localized this session)
NOT the grow (dir2_grow_inode gap-tripwire 0×). NOT the reload-adopt (post_from_disk 0× once gated). The gap is born at **`xfs_dir2_shrink_inode` freeing a NON-LAST (middle) dir data block** (xfs/libxfs/xfs_dir2.c ~1078): xfs_bunmapi removes the middle block's extent but di_size is left UNCHANGED (only the last block shrinks di_size) → a data-region GAP with di_size still large. Legitimate single-node (leaf/free-index no longer references it); becomes a durable TEAR multi-node when the block-free and the leaf update do NOT reach the platter atomically/consistently across a cross-node EX handoff (Invariant-1 violation) → a peer's stale leaf references the freed block → hole. Probe `shrink_inode_midblock` ADDED there (this build) to confirm on next run. This happens during the per-round rm-rf (entry removals) / inode reuse.

### FIX THAT LANDED (partial, net-positive, KEEP): TORN-DISK RELOAD GATE
xfs_mxfs_dlm.c, in mxfs_dlm_reload_inode just before xfs_idestroy_fork (~12788): before adopting the disk dinode, parse its EXTENTS records; if the data region (off < m_dir_geo->leafblk) has a HOLE for the SAME incarnation, REFUSE the adopt — keep in-core, set i_dlm_stale + re-arm DIR_RELOAD, return. `P-RELOAD-TORN-DISK-SKIP`. Effect: non-origin nodes keep good maps (incore_nx=9 vs torn disk_nx=3), oops ELIMINATED, no cascade. Insufficient alone: the ORIGIN node's own in-core is gapped (from its shrink) and it still flushes it (`P-IFLUSH-GAP-DETECT` ~230×) → re-torns disk.

### REVERTED (caused worse): iflush-side gap fence (skip flushing a gapped dir map)
Left the gapped in-core for xfs_dir2_leaf_addname → kernel OOPS (RIP xfs_dir2_leaf_addname+0x733, write to RO leaf page). Now DETECTOR-ONLY (`P-IFLUSH-GAP-DETECT`, xfs_inode.c).

### NEXT (RULE 4) — close the origin so the gap is never durable
The real fix must make the middle-block-free atomic with the leaf update across the handoff, OR prevent a middle-block free from leaving a durable gap that a peer's stale leaf can reference. Options to try:
1. **Don't free a middle dir data block on removal under multi-node** — keep it as an empty (logged, bestfree=BLOCKSIZE) data block in the map (like the ENOSPC branch already does at xfs_dir2.c:1057 "leave the block in the file, not binval it"). No extent removal → no gap → no tear. Scope to multi-node dirs. This is the most promising — it eliminates the gap at the source.
2. Ensure release-drain flushes the leaf+extent-map+free-index as ONE consistent image before EX unlock (GPT consult #1) so a peer never sees the half-state.
3. On dir inode REUSE (rm-rf+mkdir, new di_gen), force a full fork reset so a stale gapped fork can't survive.

### Repro: `tests/tcp/drc_reliab_iter.sh 8` (clean reboot + run; ~8-10min). Pass rate this build ~1/3.
### Instrumentation (cheap/capped): mxfs_dir_delalloc_tripwire (delalloc+gap, sites: dir2_grow_inode/post_from_disk/dabuf_map_hole/shrink_inode_midblock), mxfs_dir_hole_disk_probe (FUA DISK-TORN prover), P-IFLUSH-GAP-DETECT, P-RELOAD-TORN-DISK-SKIP.
See [[sess49-8tcp-root-is-durable-dir-delalloc-extent-tear]] [[sess22-build-1FE2C2DA-reorder-plus-holeskip-144of145-noshutdown]] [[sess47-GPT-consult-leaf-coherence-invariant-and-design]].
</body>
