---
name: sess42-REFINE-reload-always-adopts-disk-superset-no-shrink-loss-is-block-never-durable
description: sess42(ccloop) REFINEMENT: P62-RELOAD-FORK-SHRINK shrink=0 ALWAYS (reload adopts disk superset, disk_nx≥incore_nx) → candidate-A reload-orphan REFUTE…
metadata:
  type: project
---

## sess42 (ccloop) REFINEMENT — narrows candidate A vs B. Pairs with [[sess42-CAPSTONE-read-first-grant-divergence-not-data-base-is-the-frontier]].

### Trace of a fail (round 5, dirino=131, HEAVY multi-loss readdir=789: node2 lost f1/f5/f23/f30/f33/f50, node8 lost f18/f20/f26/f33/f40 — 11 entries scattered across both nodes' sequences):
`P62-RELOAD-FORK-SHRINK ino=131` across test1/test2/test8 shows **shrink=0 in EVERY instance**, with disk_nx ≥ incore_nx (e.g. incore_nx=3 disk_nx=4/8; incore_nx=4 disk_nx=7; incore_nx=8 disk_nx=9). I.e. on every reload the node's in-core extent map LAGS disk and it ADOPTS the disk superset (no shrink). 

### ⇒ Candidate A (reload ORPHANS the victim's block by shrinking the dinode extent map) is REFUTED: the reload never shrinks; a block that is durable on disk is ALWAYS adopted into the map. Therefore the victim's data block is NOT being orphaned by a reload — it simply NEVER BECOMES DURABLE ON DISK (so it's never in the disk map that every reload adopts). This is candidate B / the durability gap.

### The paradox sharpened: the block-with-entry is never durable, YET:
- `dir_release_fua_write=1` (FUA-write released dir blocks to platter) did NOT help.
- `dir_release_flush_all_done=1` (force-flush every DONE dir DATA block at release) did NOT help.
- written_seq@completion did NOT help.
- EX is serialized (P42-STALEEX-SERVE=0, held=1 at serve).
⇒ The release-drain that hands the dir to the next node DOES NOT REACH the just-added block. The drain (`mxfs_dir_data_durable`/`mxfs_dir_flush_data_blocks`) iterates `for_each_xfs_iext(&ip->i_df,...)` — the CURRENT in-core extent map. If, by the time the adding tenure releases, the just-added block's extent is NOT in the iterated map (freed/reallocated/converted by a later op in the same or next tenure, OR the map was reloaded/adopted to a version that doesn't include this node's just-added-but-not-yet-on-disk block), the drain skips it → never flushed → never durable → never adopted → lost. The HEAVY multi-loss (whole clusters of a node's entries) fits: a tenure's batch of adds to a block (or block range) whose extents get superseded by a peer's concurrent grow before this node's drain runs → the whole batch is skipped by the extent-iterated drain.

### This is EXACTLY GPT's warning: "do NOT rely on the current extent map for the release drain; track the dirty set by TENURE (xfs_trans_log_buf / xfs_trans_log_inode hooks), including FREED/converted/reused blocks." The extent-map-iterated drain has a structural hole: a block dirtied this tenure but no longer in the current extent map (or in a reloaded-smaller map) is never drained.

### NEXT (RULE 4) — PROVE the extent-iterated-drain hole:
1. Add a per-tenure dirty-dir-block SET: hook `xfs_trans_log_buf` for dir3 data/leaf/free/da3 buffers of the storm dir → record (daddr, bno, incarn) into a small per-inode ring on every modify. 
2. At the adding tenure's RELEASE, log each recorded daddr AND whether the extent-iterated drain (`mxfs_dir_flush_data_blocks`) actually visited it (compare the tenure-set to the iterated daddrs). A daddr in the tenure-set but NOT iterated = the proven hole.
3. FIX = drain the TENURE-SET (every block dirtied this tenure), not the current extent map, before handoff (GPT per-tenure checkpoint). xfs_bwrite each tenure-dirty block that's still cached+undestaged.
Build 445B37FF (probes P13-LADD/P42-RELDUR/P42-VACUOUS-DURABLE/P42-STALEEX-SERVE, all inert/storm-scoped; all fix params default-OFF = keeper functionally). Cluster clean. Criterion NOT met.</body>
