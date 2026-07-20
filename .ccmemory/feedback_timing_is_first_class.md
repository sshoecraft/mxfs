---
name: timing-is-first-class
description: Timing/timeouts are a correctness-level concern in MXFS. Slowness is a real failure; never mask it with generous timeouts. A clustered FS 100x slower than local XFS is unusable.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 335bbd54-62a5-4783-93da-29e01b327fe3
---

# Timing and timeouts are first-class — slowness IS a failure

**Rule:** Be cognizant of how long operations actually take versus how long
they *should* take. A clustered filesystem that takes 300s for something
local XFS does in 3s is useless — nobody will run it. Performance is a
ship-blocking requirement, equal in weight to correctness, NOT a "nice to
have" to defer.

**Why:** The user was emphatic about this on mxfs.1 (had it added to that
project's CLAUDE.md + memories). It's the whole reason prior MXFS attempts
(mxfs.1–4) were judged inadequate despite being "correct" — they couldn't
match native XFS performance. Correctness without competitive performance =
a filesystem no one uses.

**How to apply:**
- **Timeouts cut both ways.** A timeout set too generously *masks* the real
  problem: a 900s test watchdog will happily let a cluster with 18-20s
  mounts "pass" correctness while being pathologically slow. Don't pick a
  big timeout just to make a test finish — the timeout value encodes an
  expectation about acceptable duration.
- **The thresholds in `SUCCESS_CRITERIA.md` are the spec, not arbitrary
  caps.** Its "Threshold rule" says: if a verifier fails because the work
  is much slower than expected, *fix the FS, don't widen the threshold.*
  Timing criteria (`cluster_ops_timing`, `online_membership`,
  `single_node_paired`, `rsync_paired`, `scaling_curve`) are real
  ship-gate failures, never "known minor."
- When something is slow, **root-cause the slowness** (per RULE 4) — don't
  accept it or bump the timeout around it.
- When reporting results, treat a timing FAIL as seriously as a correctness
  FAIL.

**Live example (v5, 2026-05-29):** multi-node mount measured ~18-20s/node
on the SCST stack, failing `cluster_ops_timing` (thr 15s first / 10s rest)
and `online_membership` (thr 15s). "Mount completes in seconds" is the
spec; 18-20s is a real bug to diagnose (likely CAW probe / discovery /
lease settle time), not a threshold to relax. See [[criteria-ship-gate]]
and [[test-cluster-scst-stack]].
