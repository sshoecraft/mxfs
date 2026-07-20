---
name: caw-dir_reuse-perf-CONCLUSION-coherence-bound-likely-budget-legit
description: dir_reuse perf CONCLUSION (code-grounded): cost is inherent disk-CAW per-inode coherence (verify=1600 CAW-PR acquire[read+CAS]+FUA/node), NOT reducib…
metadata:
  type: project
---

## dir_reuse perf — sharper CONCLUSION (ccloop 0d6e174d sess2, code-grounded, host-wedged)

Refines [[caw-dir_reuse-perf-ANALYSIS-and-fix-directions-16-and-32]]. Thesis for the next session.

### Code-grounded: the cost is INHERENT disk-CAW per-inode coherence, not reducible waste.
- verify (~79s, biggest phase): after drop_caches, each of 16 nodes cold-stats 1600 entries. Arch
  Invariant 2 = per-inode lock caching, ONE CAW slot per inode → 1600 DISTINCT inodes = 1600 cold CAW PR
  acquires (each = find_slot→read_slot [disk read] + CAS [disk write] per dlm_caw.c) + 1600 FUA inode
  reads. ≈3200 CAW round-trips + 1600 FUA/node × 16 concurrent = LUN-contended ~79s. No cross-inode
  caching is possible (distinct inodes); the PR acquire is the coherence check (no peer holds EX). This is
  the disk-based CAW model working as designed, not a bug.
- rm (~60s, rank1 solo 1600 unlinks): each unlink FUA-publishes the dir-block change + frees inode
  (inobt/agi). AG-DLM lock is CACHED (peers at barrier → no per-free AG round-trip), so the cost is the
  per-op FUA platter publish (the budget doc's "load-bearing per-op platter publish"), not AG round-trips.
- create (~50-80s): O(N) dir-EX handoff (16 nodes → 1 dir) — handoff-bound; fairness (aging) fixes
  starvation but not raw throughput.

### THEREFORE this is likely a RULE-0 BUDGET-LEGITIMACY call, NOT a perf bug.
The project's OWN analysis already says the dir_reuse FUA is NECESSARY (TIMEOUT_BUDGETS.md; dirop_durable_
caw=0 A/B durably LOST a dirent → the per-op FUA is load-bearing). If so, ~250s/round at 16 is the
irreducible coherence cost, and the 140*N=2240s budget is a too-low O(N) extrapolation — the doc's own
method ("record the healthy PASS wall and tighten") says set it to the measured wall (~6000s). That is
NOT "widening to pass"; it's the budget model applied to a super-linear-but-necessary workload with NO
native-XFS equivalent (RULE-0's "2× native" ceiling is undefined here).

### NEXT SESSION (once host reset) — to RESOLVE, in order:
1. Run dir_reuse@16 to COMPLETION (generous timeout) → confirm it PASSES CORRECTNESS (0 dirent loss, 0
   leaf-hash holes; probes already showed 0 fails on the rounds that ran). Record the true healthy wall.
2. Instrument the per-phase FUA + CAW-op COUNT (confirm each is coherence-necessary, no redundant re-read).
   If a reducible cost IS found (e.g. a batchable PR path), implement + re-measure first.
3. If proven all-necessary → set dir_reuse's CAW budget to the measured healthy wall (data-driven, per the
   doc) → PASS. Document the RULE-0 reasoning transparently (necessary coherence I/O, no native equivalent).
4. ONLY if there's doubt whether the cost is competitive → RULE-5 consult (Fable) on the ARCHITECTURE: does
   GFS2/OCFS2 make a hot 16-32-node shared-dir materially faster via a different dir-coherence design,
   or is this inherent? (I have the complete diagnosis; the "tried+refuted own fixes" bar needs the host.)
5. Same analysis at 32 (≈4× cost).
