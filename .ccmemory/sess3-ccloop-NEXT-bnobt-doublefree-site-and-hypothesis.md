---
name: sess3-ccloop-NEXT-bnobt-doublefree-site-and-hypothesis
description: sess3(ccloop) SHARP: dir_reuse 4/tcp bnobt double-free CORRELATED via P3-EFREE-Q — SAME inode incarnation (ino132 gen X) frees SAME extent [11,2] twi…
metadata:
  type: project
---

## sess3 (ccloop) — bnobt double-free CORRELATED (RULE 4, decisive). The deterministic-ish dir_reuse 4/tcp blocker.

### THE DATA (build 461923D5, P3-EFREE-Q queue-probe @ xfs_bmap.c:5406 + P15-INSTR @ xfs_alloc.c:2254):
```
P15-INSTR FREE-AG-EXTENT-FAIL-LEFT comm=dd agno=0 bno=11 len=2 ltbno=11 ltlen=5  (freeing [11,2] fully inside already-free [11,5])
P3-EFREE-Q history for agbno=11 (test1):
  ino=133 gen=4062149531 agbno=11 len=3 comm=rm
  ino=133 gen=945785204  agbno=11 len=3 comm=rm   (ino133 reused across 4 gens, all free agbno=11)
  ino=133 gen=584235551  agbno=11 len=3 comm=rm
  ino=132 gen=2617413979 agbno=11 len=2 comm=dd   <-- first free
  ino=133 gen=1097273653 agbno=11 len=3 comm=rm
  ino=132 gen=2617413979 agbno=11 len=2 comm=dd   <-- SECOND free (SAME ino+gen+extent, 7s later) = DOUBLE-FREE
```
### ROOT: The SAME inode incarnation (ino 132, gen 2617413979) freed the SAME extent [11,2] TWICE. agbno=11 is a HOT low block reused constantly across incarnations (ino 133 with 4 gens, ino 132). The second free hits [11,2] while it is ALREADY in the free tree (ltbno=11 ltlen=5). Meaning: inode 132 ALLOCATED [11,2] from an AGF/bnobt that STILL showed those blocks FREE (a stale/incoherent AGF — the prior free by a peer/incarnation wasn't coherently reflected when 132 allocated), so when 132 frees them the bnobt reports double-free → xfs_defer_finish corruption → SHUTDOWN → cascades to fault tests at 4/8. = the deep pre-existing bnobt AG free-space cross-node coherence residual (sess42/43/47/24 "both nodes alloc overlapping AG ranges").

### HEISENBUG: dir_reuse 4/tcp is FLAKY (~1-in-3 fail from clean reset; the drc3 3/3-fail was accumulated post-suite-churn). The P3-EFREE-Q pr_warn PERTURBS timing (2/2 pass then caught on run 3) — instrumentation in the free path hides/rarefies the race (consistent with project-wide "instr masks the race"). Any fix must be timing-robust, not a delay.

### FIX DIRECTIONS (next session):
1. **AG free-space coherence** (root): ensure the AGF/bnobt this node reads for ALLOCATION reflects peers' recent frees/allocs (fresh under AG-DLM). Study sess42 (C6970FF9 b_mxfs_ag_gen advance only when fresh), sess43 (BB54A138 in-AIL AG-meta not discarded), sess24 (P33 both-nodes-overlapping-AG-ranges). Likely a stale cached AGF/AGFL buffer served an allocation of already-free-elsewhere blocks.
2. **Defensive (pragmatic unblock, evaluate safety)**: in xfs_free_ag_extent @ xfs_alloc.c:2254, when the range is FULLY already-free (ltbno+ltlen >= bno+len) under multi-node, SKIP the redundant free (blocks are already correctly free; keep AG counts consistent) instead of XFS_IS_CORRUPT shutdown. Prevents the shutdown+cascade. RISK: masks the alloc-side incoherence + AGF freeblks accounting must stay correct — verify carefully. Only skip on EXACT/CONTAINED overlap (genuinely already free), never partial.

### Probes in tree: P3-EFREE-Q (xfs_bmap.c:5406, AG0 free-queue), P15-INSTR (xfs_alloc.c:2254). Build 461923D5 (adds P3-EFREE-Q to 24EDC1F3's 2 fixes). Correlation harness: /tmp/drc_catch.sh.
See [[sess3-ccloop-HANDOFF-two-fixes-2tcp-17of17-dir_reuse-residual-defer_finish]] [[sess42_lessons]] [[sess43_lessons]] [[sess24_lessons]]
