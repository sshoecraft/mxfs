---
name: feedback-a-release-requires-every-board-row-pass-no-flaky-no-skip
description: User: ANY release needs every suite row PASS on the release build. FLAKY is not a grade; a SKIP (e.g. missing perf baseline) is not a pass.
metadata:
  type: feedback
tags: [release, board, verification, flaky, skip]
---

User correction, 2026-09-28, on reviewing the 0.90.7 "2-node CAW released" commit:

> these are required for ANY release ... there can be no such thing as FLAKY

What the 0.90.7 run shipped with, and why each one fails that bar:
- `alloc_witness`, `chk_clean`, `crash_audit` graded FLAKY on the 2/CAW board. The session said every failure was the harness, fixed the harness, and released while the board still carried the failures. A harness fix does not turn a row into a PASS. The row has to PASS, cleanly, on the build being released.
- `fio_perf_vs_xfs` was SKIPped because no native-XFS baseline had been captured on the rig. That means performance against the 2x-native ceiling was never measured. A missing baseline is work still owed: capture it, then run the row.
- `dlm_lock_correctness` SKIPped on the board and passed only in a separate run afterwards. A pass outside the board run does not replace the row on the board.

How to apply:
- Before claiming a release, or writing criteria-met=YES for a release goal, every row of every suite the release covers must read PASS on the release srcversion. Any FLAKY, SKIP or FAIL blocks the release.
- A board that "keeps a failure for N runs" and has no way to discount a harness defect is not a reason to release past the failure. Re-run until the window is clean, or fix the grading. Either way the release waits.
- Neither the defect-queue filter (`tools/defects.py 2 caw --release` coming back empty) nor a loop's own criteria-met judgement is enough without a board that is all PASS.
