---
name: trap-a-vacuity-precondition-printed-as-a-fail-line-makes-the-capture-gate-score-the-harnesss-own-vacuous-verdict-as-broken
description: TRAP (s70c): d0932_retire_pending/owner_depart printed "  FAIL <state not reached>" then RESULT: VACUOUS; the gate counts VACUOUS only with zero FAIL…
metadata:
  type: feedback
tags: [capture-gate, vacuous, harness-shape]
---

# A vacuity precondition printed as a FAIL line makes the gate score the harness's own VACUOUS as BROKEN

**Where it bit (s70c, chain gate_s70c):** tests/d0932_retire_pending_takeover.sh and tests/d0932_owner_depart_takeover.sh both check "is the state this lap needs standing on the platter?" with `ckge` (which prints `  FAIL ...` when it is not), and then, on the same condition, print `RESULT: VACUOUS` and exit 3. tests/capture_fault_gate.sh counts a healthy lap as VACUOUS only when it exits 3 with ZERO `  FAIL` lines; otherwise it is BROKEN. Both entries therefore scored BROKEN on a lap that the harness itself had judged a non-measurement — the same at s53b and s59h, which is why those entries never showed OK in the gate table.

**Why the state is unreachable in those shapes (and VACUOUS is honest):** a clean unmount serialises against the node's own parked fence/recovery work (measured s578j, s70c: the umount blocked for the whole hold, then the prover/owner finished and published, and the departure left nothing standing). The "departed prover/owner with a standing attempt" state cannot be produced by a hold shorter than the departure. The safety property that matters (no consumable slot published while the attempt is outstanding) is asserted earlier in the lap and PASSes.

**The rule:** a check that decides whether the lap can measure anything is a PRECONDITION: print it as a `STAGE ...` line with the count, then take the VACUOUS exit. Reserve `ck`/`ckge` (FAIL lines) for assertions about MXFS on a state that was reached. The gate's contract: exit 0 = OK, exit 3 + no FAIL lines = VACUOUS (counted apart, not BROKEN), exit 1 or 2 or any FAIL line = BROKEN.
