---
name: sess14run-8tcp-dir_reuse-root-is-NODE-format-dir-coherency-small-dir-passes
description: sess14(ccloop) 8/tcp dir_reuse ROOT LOCALIZED: readdir=0/800 for ALL nodes (incl creator) is NODE/btree-format dir coherency. DRC_NFILES=10 (EXP=160,…
metadata:
  type: project
---

## sess14 (ccloop) — 8/tcp dir_reuse root = NODE/btree-format directory coherency

### PROVEN by isolation (build AA8C4934)
- dir_reuse 8/tcp, DRC_NFILES=50 (EXP=2×8×50=800): **readdir=0/800 on EVERY node incl rank1 the creator, every round, no shutdown, lookup_fail=0**. The dir reads TOTALLY EMPTY after `drop_caches` — even the creator loses its own just-created (and sync'd) files on cold re-read.
- dir_reuse 8/tcp, DRC_NFILES=10 (EXP=160): **PASS 8/8, zero fails.**
=> The failure is specific to the LARGE dir. ~800 dirents (~13KB) pushes the dir into LEAF→NODE (btree) format; the small 160-entry dir stays LEAF/BLOCK. So the 8-node dir_reuse blocker is **NODE/btree-format directory coherency**, NOT a general 8-node coherency bug (cache_coherency, cross-node file content, etc. all pass 8/8).

### Why readdir=0 (not partial) for NODE format
A NODE-format dir has its data fork in BTREE format (extent map is a btree, not inline) + a multi-block leaf hash index + a btree dir index. readdir=0 (nothing traversed) implies the reader can't resolve the dir's blocks at all — likely the btree-format data-fork EXTENT MAP or the dir btree root is read stale/empty after the cold reload, so xfs_readdir traverses nothing. This connects to the readdir reload (xfs_dir2_readdir.c) and DABUF_MAP_HOLE family: for btree-format data forks, mxfs_dlm_reload_inode + xfs_iread_extents must re-read the btree blocks coherently; if the reload adopts an empty/stale btree root the whole dir reads empty.

### NEXT (RULE 4)
Instrument the NODE-format readdir at 8 nodes: log dp->i_df.if_format, if_nextents, i_disk_size, and the dir-btree root daddr at readdir time (the creator should have non-zero). Determine whether (a) di_size/nextents read as 0 (stale inode adopt), (b) the btree extent map is empty (xfs_iread_extents reads stale btree root), or (c) the leaf/data blocks are stale. Compare creator vs cold-reader. The fix is likely making the btree-format dir extent-map + btree-index reload coherent (the inline-extent path works; the btree path is the gap).

### INFRA: 8-node runs frequently WEDGE the mxfs module on nodes (rmmod busy after FS-shutdown/heavy run). Clears only via `virsh -c qemu:///system destroy <node>; virsh ... start <node>`. Reboot wedged nodes between 8-node runs.

### Criterion: 1/tcp ✅ 2/tcp ✅ 4/tcp ✅ 8/tcp ✗ (NODE-dir coherency [dir_reuse] + bnobt [crash_consistency] + 8-way throughput). NOT met.
See [[sess14run-8tcp-10of17-clean-run-bnobt-is-the-blocker-DABUF-gone]] [[sess14run-FIX-readdir-dabuf-map-hole-gen-bump-before-reload-bail]].
