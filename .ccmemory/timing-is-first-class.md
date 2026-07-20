---
name: timing-is-first-class
description: RULE 0 (sess130): timeouts are performance assertions. budget = infra + 2×native-XFS. Timeout = FAIL even with 0 errors. tests/criteria/TIMEOUT_BUDGE…
metadata:
  type: feedback
---

# Timeouts are performance assertions (RULE 0)

**User directive, repeated ~10×, finalized sess130 as RULE 0 in /src/mxfs/CLAUDE.md.**

**Why:** Native XFS rsyncs ~700MB in 3-4s on this hardware. A clustered FS slower than
2× native is unshippable — nobody uses GFS2/OCFS2 because they're too slow. A blanket
590s/600s timeout on seconds-scale work hides exactly the failures that matter.

**How to apply:**
1. Before running ANY test: write its budget = infra (measured boot/mkfs/mount/ssh) +
   workload (native-XFS equivalent × 2). Budgets table: `tests/criteria/TIMEOUT_BUDGETS.md`.
2. Set the Bash timeout TO the budget. Not a round number, not the tool cap.
3. A timeout IS a FAIL, even with zero errors. Kill, record FAIL, diagnose slowness
   as a first-class bug (RULE 4 loop).
4. 2× native XFS = hard ceiling. XFS 7s vs mxfs 200s = FAIL even if bytes are correct.
5. NEVER widen a timeout to make a run pass; never re-run with a bigger timeout
   "to see if it finishes".
6. After each healthy PASS, record actual wall in TIMEOUT_BUDGETS.md and tighten.

Measured baselines (sess130): mkfs 0.6s; first mount 2.7s; later mounts 4.8s;
umount 0.4s; VM power-cycle→ssh ~40-50s; 4-node fresh_cluster_mount ~60s.

Internal-timeout debt: barrier_wait 120s (should be ≤15s), MXFS_CAW_WAIT_TIMEOUT_MS=120s.

Supersedes/merges [[feedback_timing_is_failure]]. Related: [[criteria-ship-gate]]
