---
name: trap-a-row-that-fails-right-after-a-budget-killed-row-is-collateral-until-the-earlier-row-is-read
description: TRAP (0.90.14/16, 4/tcp): crash_audit FAILed twice only because chk_clean was killed at its budget with the fleet unmounted; the board counted it as…
metadata:
  type: feedback
tags: [board, flake-window, crash_audit, chk_clean, harness]
---

# A row that fails right after a budget-killed row is collateral until the earlier row is read

**What happened (4/tcp, runs 20260928T221236Z and 20260929T004057Z):** chk_clean was
killed at its 180 s budget (the umount wedge, a real MXFS fault) and left every
node unmounted.  The next row, crash_audit, is host-coordinated and had no
pre-assertion: its death oracle aborted at its own "member not mounted" check
before any kill, the row recorded that as "the death oracle passed ... got 2"
and "acked >= 1 got no(none)", and the board counted TWO genuine crash-recovery
failures in the flake window for a row that had measured nothing.

**How to read it:** `tools/criteria.py` excludes only reasons matching
`pre-assert|NO_TERMINAL_RECORD|run was killed|prep fail` from the flake count.
A row's own precondition abort phrased any other way counts as genuine.  So
when a row FAILs in the same run as a budget-killed row that precedes it, read
the earlier row's evidence first (`tests/evidence/run_<row>_<RUN>/*.rc` all
124 = killed) and the later row's log for a precondition abort before treating
the later FAIL as a defect of the mechanism it tests.

**Fix in the tree (0.90.17):** run.sh's host-row runner (`run_host`) makes the
same mount-and-readdir pre-assertion the coordinated runner makes and records
FAIL "pre-assert", which the board excludes.  The two collateral FAILs were
annotated with `tools/criteria.py amend` (the run stays FAIL in the history,
only the flake rule stops counting it).
