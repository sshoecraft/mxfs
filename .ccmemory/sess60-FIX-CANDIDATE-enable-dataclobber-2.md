---
name: sess60-FIX-CANDIDATE-enable-dataclobber-2
description: sess60: dataclobber=2 REFUTED for node1_f1 — guard barely fires (DCSKIP~0/round), failures INCREASE (perturbs timing). Clobber is current-tenure (bge…
metadata:
  type: project
---

## sess60 — dataclobber=2 REFUTED as the node1_f1 fix

Tested `MXFS_EXTRA_MODARGS='dataclobber=2' ./run.sh 4 tcp dir_reuse_coherency`
(build EB619331, clean cluster). RESULT by round 7: drcFAIL=3-5 PER NODE (WORSE
than gen-bump-only build A1419A72 which had ~1-2 total), and P-DATACLOBBER-SKIP
fired only ONCE total (test3=1) across 7 rounds.

### Conclusion
The writeback stale-tenure clobber guard does NOT catch the node1_f1 loss:
- DCSKIP barely fires => dc_stale (b_mxfs_dir_gen < dir's i_dlm_dir_gen) almost
  never true at the clobbering write => the clobber is a CURRENT-TENURE write
  (bgen == dir_gen), not a prior-tenure stale buffer.
- The disk-read-per-dir-write PERTURBS timing and exposes MORE races (failures
  up) — do NOT make dataclobber default; it is net-negative here.

### What this means for the root (all writeback-stale-tenure ruled out now)
node1_f1 durable loss is NOT: reader stale-serve (GENMATCH=0, DIR-STALE-SKIP=0),
release-drain-gap, conversion-drop, double-conversion, NOR stale-tenure
writeback clobber (dataclobber). The clobbering operation runs in the CURRENT
tenure on a CURRENT-gen block. So the dirent-add for node1_f1 is undone by a
later CURRENT-tenure op that RMWs a block whose gen MATCHES (so no
invalidation/re-read fires) yet does not contain node1_f1 — meaning node1_f1
was never merged into the version that node holds, OR a free-space/bestfree
miscompute reuses node1_f1's slot. node1_f1's INODE exists (dd created it) but
its DIRENT is gone from BOTH leaf-hash and data block (LOOKUP_ENOENT +
REREAD_MISS) = orphaned inode.

### NEXT hypotheses (untried)
1. Free-space/bestfree: a current-gen block0 RMW computes freespace from a base
   that lost node1_f1's slot, placing a new entry over it. Instrument
   xfs_dir2_data_use_free / bestfree at add for the shared dir.
2. Logical-block0 SPLIT (sess42): node1_f1's dirent lives in a data block at a
   different fsb than the one the home dinode's logical-0 resolves to (extent
   map divergence across nodes). The leaf hash maps to logical-0; if logical-0
   points to the WRONG physical block, lookup+readdir both miss it. Re-examine
   the extent map / xfs_dabuf_map for block0 across nodes at a failing round
   (sess42 saw node1 fsb15 / node2 fsb14). This is the strongest untried lead
   given everything else is refuted and it explains LOOKUP_ENOENT + REREAD_MISS
   without any read/write staleness probe firing.
3. Concurrent dirent-add lost-update at the transaction level (two nodes' adds
   to the same logical block via a path that bypasses the gen invalidation).

Keep crash fix + readdir gen-bump (EB619331). dataclobber stays default 0.
See [[sess60-residual-writer-side-durable-node1f1-clobber]],
[[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]].
