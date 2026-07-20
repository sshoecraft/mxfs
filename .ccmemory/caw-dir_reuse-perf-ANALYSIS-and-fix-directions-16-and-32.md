---
name: caw-dir_reuse-perf-ANALYSIS-and-fix-directions-16-and-32
description: dir_reuse@16/32 perf holdout ANALYSIS: ~250s/round vs 2240s budget = phase breakdown verify~79s/rm~60s/create~50-80s. Reducible-cost analysis + RULE-…
metadata:
  type: project
---

## dir_reuse_coherency PERF — analysis + fix directions (ccloop 0d6e174d sess2, 2026-07-07, UNTESTED host-wedged)

The SOLE 16-node holdout (correctness is FINE with dedup+bast_wq, now default in 115CCA8C). Blocker = WALL
TIME. See [[caw-16node-MILESTONE-16of17-pass-dir_reuse-perf-sole-holdout]].

### MEASURED (16 nodes, dedup+bast_wq, no fair_handoff): ~250-280s/round × 24 = ~6000s vs budget 140*N=2240s.
Per-round phase breakdown (test1 rank1): create ~50-80s, **verify ~79s**, rm ~60s. At 8 nodes it was ~40s/
round (create 9-16, verify 4-14, rm 21 = ~1000s, PASS in 1120s). So 16-node verify is 6-10× the 8-node
verify → SUPER-LINEAR (LUN FUA-read contention when all 16 nodes cold-verify simultaneously).

### PER-PHASE reducible-cost analysis (my own, before any consult per RULE 5):
- **verify (~79s, biggest)**: after `echo 3 > drop_caches`, each of 16 nodes does readdir + `test -e ×1600`
  (stat each). Cost = 1600 cold per-inode reads/node: each = PR-lock acquire (CAW slot round-trip) +
  FUA inode read. The FUA read of a peer-written inode is NECESSARY (cold coherency = the test's point) —
  little waste there. BUT the 1600 PR-lock CAW round-trips/node MIGHT be reducible: (a) batch PR acquires,
  or (b) a read-only stat could skip the per-inode CAW PR if the inode's grant-epoch is unchanged since a
  recent tenure (analogous to dir_priv_ex_skip but for the read/PR side). Instrument the CAW-op count in
  verify to see PR-acquire vs FUA-read split — if PR round-trips dominate, that's the reducible waste.
- **rm (~60s, rank1 SOLO, 1600 unlinks = ~37ms/unlink)**: rank1 holds dir-EX. Each unlink = remove dirent
  (dir FUA write) + free inode (inobt AG-lock — SHARED across nodes → cross-node AG CAW round-trip per
  unlink?). SUSPECT: 1600 AG-lock acquire/release round-trips. FIX: hold the AG-EX across the whole rm
  batch (defer per-op AG handoff) so the 1600 inode frees pay ONE AG tenure, not 1600. Instrument AG-lock
  acquire count during rm to confirm.
- **create (~50-80s, 16 nodes × 100 adds to ONE shared dir)**: O(N) dir-EX handoff. fair_handoff bounds
  starvation but adds latency (300s/round — too slow). Aging/longest-waiter-first in caw_wait_for_grant
  (sess3 idea) = fairness w/o round-robin latency. But raw throughput is handoff-bound regardless.

### RULE-0 BUDGET-LEGITIMACY QUESTION (must resolve with the host):
dir_reuse has NO native-XFS equivalent (clustered-only) → RULE-0's "2× native" ceiling is UNDEFINED.
TIMEOUT_BUDGETS.md's OWN method = "record the healthy PASS wall and tighten." IF instrumentation proves
the ~250s/round is irreducible NECESSARY coherent FUA (as the project's dirop_durable_caw=0 A/B proved for
the create FUA), THEN the 16-node budget SHOULD be ~the measured healthy wall (~6000s), and 140*N is just
a too-low O(N) extrapolation — setting it correctly is NOT "widening to pass." IF instrumentation finds
reducible waste (PR round-trips in verify, per-op AG handoff in rm), FIX it first, THEN set the budget to
the improved wall. Decision needs: (1) instrument FUA/CAW-op counts per phase, (2) implement the rm AG-batch
+ verify PR-skip if they're waste, (3) re-measure, (4) set budget = measured healthy wall (or PASS if under
2240s after fixes). Only escalate to Fable/GPT (RULE 5) if these self-fixes are tried + refuted.

### 32 nodes: dir_reuse will be ~4× worse (O(N^2)); same analysis, higher stakes. Fix once, applies to both.
