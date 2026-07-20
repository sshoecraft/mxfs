---
name: sess61-zsl-root-di-ahead-of-bmbt-leaf-ordering
description: sess61 PROVEN: zsl root = dinode di_nextents=N reaches shared disk BEFORE matching bmbt leaf (N-1); reloader trips ir.loaded!=if_nextents. 2 fix hyps…
metadata:
  type: project
---

## sess61 (ccloop 14d31183) — zero_silent_loss root proven; 2 hypotheses refuted

Builds on [[sess60-zsl-bmbt-leaf-write-essentially-never-submitted]] and
[[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]]. Criterion STILL FAILS
(silent=1600 every run). Marker NOT written.

### Decisive instrumentation added (KEEP — all low-volume, BTREE-only)
- **P61-BMBTSCAN** (xfs_mxfs_dlm.c mxfs_dir_bmbt_scan flush path): logs per
  release `if_nextents seen leaf leafrecs cand wrote mode` for the dir's bmbt
  leaves. Always-on rate-limited.
- **P61-CHOKEPOINT-SKIP-BMBT** (pal/linux/xfs_buf.c xfs_buf_submit_bio): NL-skip
  guard at the bio chokepoint (see refuted FIX-1).
- **P61-BIO-OVER-LOGGED-BMBT** (xfs_buf.c, after P110 block): bmbt read-over-
  logged guard (see refuted FIX-2).

### PROVEN ROOT (single stable leaf, no aliasing)
For the shared storm dir ino=131: ONE bmbt leaf, ONE stable daddr per run
(e.g. 16698680). The on-disk **dinode di_nextents reaches N while the on-disk
bmbt leaf only reaches N-1**. Reloaders read di=N, walk leaf=N-1 →
`ir.loaded(N-1) != if_nextents(N)` at xfs_bmap.c:1286 (xfs_iread_extents) →
EFSCORRUPTED → FS shutdown → whole-storm cascade = the 1600 "silent" count
(blast radius of one early shutdown, NOT 1600 individual losses).
- Run d (build BA1771B9): dir grew to 16, **di=16 flushed to disk but NO node
  ever wrote leaf=16** (P60-BMBTWRITE max numrecs=15; P61-BMBTSCAN max
  if_nextents seen=15). 91× `P59-IREAD loaded=15 if_nextents=16`. The 16-grower
  bumped di_nextents=16 (flushed via xfsaild inode-cluster write) but its
  leaf=16 stayed dirty/un-flushed when the cascade killed everything. =>
  **dinode is published to the shared SCST cache AHEAD of the bmbt leaf.**
- Run c (build B973EC61): the grower test12 had in-core `iext=18 / leaf=17`
  (P61: if_nextents=18 leafrecs=17 cand=1 wrote=1) — in-core leaf one record
  BEHIND its own iext tree; it flushed leaf=17 + dinode=18. Same di-ahead-of-
  leaf disk result, different proximate (in-core leaf desync vs un-flushed).

### REFUTED this session (RULE 4 — do NOT retry)
1. **FIX-1 NL-skip at bio chokepoint** (mxfs_buf_xfsaild_skip_bmbt_write moved
   to xfs_buf_submit_bio). Hypothesis: EX→NL race lets a stale leaf write land
   (sess60 saw owner=131 numrecs=20 mode=0). Result: P61-CHOKEPOINT-SKIP fired
   **0×** on clean-cluster runs; all P60-BMBTWRITE were mode=5(EX). Mode=0
   writes were a contaminated-cluster artifact. Guard is harmless (kept) but
   not the fix.
2. **FIX-2 bmbt read-over-logged guard** (refuse plain-bio READ that would DMA
   stale disk over a bmbt leaf carrying uncheckpointed mods — bmbt analogue of
   the sess110 AG-meta guard). Hypothesis: an XBF_DONE-clear + re-read reverts
   the dirty leaf 18→17. Result: **P61-BIO-OVER-LOGGED-BMBT fired 0×** — the
   plain-bio read is NOT the revert vector. (Guard kept; safe, never fires.)

### KEY FACTS
- fua_disable=1 ⇒ all reads hit the COHERENT SCST cache; the di=N/leaf=N-1 is a
  GENUINE on-disk inconsistency seen identically by every node (not a per-
  initiator cache artifact). Reader-side FUA re-read CANNOT fix it.
- The standard XFS add path (xfs_bmap_add_extent_hole_real case 0, line 2848)
  keeps iext++ and xfs_btree_insert in lockstep when cur!=NULL — so in pure XFS
  iext and the leaf never diverge. Run-c's in-core divergence implies an MXFS
  path (suspect: the ILOCK-drop-across-CAW-poll in alloc, design-tension in
  CLAUDE.md) bumps if_nextents without landing the leaf record, OR an evict/
  reload desyncs them. NOT yet pinned.

### NEXT (writer-side ordering — the real fix direction)
The reloader sees di_nextents AHEAD of the leaf because the inode-cluster
(dinode) is published to the shared store BEFORE the bmbt leaf. Fix must COUPLE
them: for a BTREE-format dir inode, the matching bmbt leaf must be durable
BEFORE (or atomically with) the dinode's di_nextents. Candidates:
  (a) inode-flush ordering hook: before the inode-cluster write submit lands a
      BTREE dir dinode, ensure its owning bmbt leaves are durable (flush-first).
      Risk: blocking I/O in xfs_buf_submit hangs (sess44) — must be non-blocking
      or deferred.
  (b) synchronous bmbt-leaf flush at extent-grow commit (publish leaf-then-
      dinode), so di_nextents never outruns the leaf on the shared store.
  (c) pin/hold the dinode write until leafsum==di_nextents is durable.
Pin run-c's iext/leaf in-core desync separately (probe the bmapi/alloc path
that bumps if_nextents across the ILOCK-drop CAW poll).

### INFRA
Every shutdown storm re-wedges most nodes (mxfs module stuck loaded, umount
hangs). `virsh -c qemu:///system destroy+start` ALL 16, wait ~38s, all 16 come
back clean with NFS /src + fresh module (mod=0). Storm = scripts/
sess88_workload_a_modeN_baseline.sh /src/mxfs/mxfs.ko 100 1 1 (iters=1, ~50s
wall once mounted). Current build BA1771B9 (3 probes/guards in, none harmful).
</body>
