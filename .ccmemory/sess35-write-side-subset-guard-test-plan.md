---
name: sess35-write-side-subset-guard-test-plan
description: sess35 REFUTED: dir_subset_guard=1 WEDGES round-2 create (P26-SUBSET-SKIP fired 10× then deadlock — suppressed write the create depends on). Write-si…
metadata:
  type: project
---

## sess35 — write-side dir_subset_guard test: REFUTED (WEDGE).

### Result: dir_subset_guard=1 (build 734EAB23 + param) WEDGES.
- iter1 round1 PASSED (no loss); P26-SUBSET-SKIP fired 10× on test1 (caught stale writes). BUT test1 then WEDGED at round2 create-start (stuck >3.5 min, peers waited at barrier). The suppressed write (P26 skip) leaves a buffer the create synchronously depends on → deadlock. Also pathologically slow (per-write FUA disk read).
- So write-side SUPPRESSION (subset_guard) = REFUTED (wedge), consistent with sess22's "suppression is the corruptor" and read-side addname_epoch_refresh REFUTED (readdir=0). Neither refresh-the-reader nor suppress-the-writer works cleanly.

### KEEPER BUILD: 6ABE6DEE (= epoch-never-0 fix in dlm.c dg_grant_ex KEEP + EVDECIDE epoch-field diag KEEP + P37-STALEBMAP RE-GATED to instr). dir_subset_guard/dir_addname_* all DEFAULT OFF. This build == 2EAA0090 behavior (4/5 dir_reuse 8/tcp) PLUS epoch-never-0 (harmless, activates per-block machinery from first tenure). NOT yet re-verified at 4/5 but epoch fix is additive.

### SOLUTION SPACE NARROWED (all refuted this/prior sessions):
- read-side KEPT-stale-base evict: refuted (staleprt=0).
- read-side stale-bmap reload: refuted (P37=0).
- read-side addname refresh: refuted (readdir=0 / insufficient).
- write-side suppression (subset_guard, dataclobber, stale_incarn): refuted (wedge/catastrophe).
- The loss is WITHIN-tenure (sess32), durable, all-coherent, round-1 fresh-dir-growth, ~20%/round-1.

### NEXT = GPT-5.5's ORDERED RELEASE-PUBLISH (untried, NOT suppression/refresh):
On dir-EX release/BAST, checkpoint the home image in dependency order with flushes between phases, THEN advance gen:
  Phase1 flush dir DATA blocks → blkdev_flush;
  Phase2 flush leaf/freeindex/dabtree → blkdev_flush;
  Phase3 flush inode bmap+dinode → blkdev_flush;
  Phase4 advance publish gen; retire ALL clean dir BLIs.
Rationale: the next EX holder then always cold-reads a fully-consistent durable image (data ↔ freeindex/bestfree ↔ leaf ↔ di_size all same generation) so no stale free-slot pick / no stale reflush — WITHOUT suppressing any write or refreshing mid-modify. Implement in the dir release-drain path (mxfs_dir_data_durable / bast release in xfs_mxfs_dlm.c ~1103/2061). Confirm with drc_repro_loop.sh 15 "" 2 then full 24-round + tests/run_criteria_tcp.sh.
See [[sess35-HEAD-handoff]] [[sess35-GPT-consult-round1-epoch0-disables-staleevict-fix]].
</body>
