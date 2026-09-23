---
name: trap-two-board-rows-tied-by-the-run-id-must-run-in-one-run-sh-invocation-or-the-second-reads-indeterminate
description: TRAP (s72): alloc_witness then chk_clean run as two ./run.sh calls got two run ids; chk_clean refused the witness (INDETERMINATE "belongs to run X")…
metadata:
  type: feedback
---

# Two board rows tied by the run id must run in one run.sh invocation

**What happened (s72, D-THE-CLUSTERED-STRUCTURAL-AUDIT-GATE).** The witness row seals its record under `tests/evidence/alloc_witness/<run id>/` and chk_clean looks up the witness by ITS OWN run id (`MXFS_COORD_PREFIX` field 3), refusing any other as INDETERMINATE — by design, so a stale witness can never dress a later audit. Session 72 ran `./run.sh 2 tcp alloc_witness` and then `./run.sh 2 tcp chk_clean`: two invocations, two run ids (20260919T182412Z vs 20260919T182607Z), and the audit reported `release=INDETERMINATE reason=witness belongs to run ...` — which the record then described as "INDETERMINATE as designed for an INSUFFICIENT witness". It was not; an INSUFFICIENT witness yields VACUOUS. The tie was working, the invocation was wrong.

**The rule.** `run.sh <N> <dlm> [test ...]` takes a list; rows that share evidence by run id go in ONE call: `./run.sh 2 tcp alloc_witness chk_clean`. A full board run does this through the manifest order. Any harness that reads another row's record by run id (grep `MXFS_COORD_PREFIX` in tests/tooling) has the same requirement, and its INDETERMINATE reason text names the mismatch — read the reason before calling it a design outcome.
