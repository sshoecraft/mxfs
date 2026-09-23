---
name: vacuous-pass-the-dominant-evidence-failure-in-this-project
description: SYSTEMIC (sess479-480): six harnesses reported PASS/DONE for work never performed. Confirm the step RAN before reading any verdict.
metadata:
  type: feedback
tags: [harness, evidence, vacuous, rule6, verification]
---

# The vacuous PASS is this project's dominant evidence failure

Six instances across two sessions, all independent, all capable of producing a
false disposition.

## sess479 — four instances

1. **Unprepped fleet scored as failures.** Chain 116 `s479a` ran all four arms
   after `run.sh` returned rc=3 (host preflight refused the run) and reported
   `fails=12`. A build whose fix was already proven read as a regression.
   Fixed: `prep_arm()` in chains 105/116/117 records **no verdict** and stops.

2. **An assertion that could never pass.** `$vslot` in single quotes made the
   remote grep search for the literal `slot $vslot`; the line was in every
   capture and read as absent for as long as the assertion existed.

3. **An ordering gate that opened early.** Chain 117's `... | grep -qv '^0$'`
   means "some output line is not exactly 0" — true for ANY unexpected line,
   false for empty output, never a numeric test. The peer wrote and released
   before the holder existed, so the arm measured a peer write against no
   holder — the exact vacuity it had been rewritten to avoid.

4. **Three fault-injection matrices that injected nothing, all reported PASS.**
   `tmpfile_churn_kill.sh` chains 85/89/100: every victim probe read
   `iclus_marked=0 iclus_unmarked=0 P282=0`, fleet sum 0, and each arm printed
   `VERDICT PASS`. Root: the churn is `O_TMPFILE -> write -> linkat -> unlink`,
   so a file is named only between the linkat and unlink of one loop iteration
   (sub-millisecond); the peer meant to provoke the release listed the
   directory on 3 laps 0.7 s apart and read `entries=0` every time.

## sess480 — two more, and the worst shape yet

5. **A board from the PREVIOUS DAY reported as this build's result.** Chain 119
   (`s480a`) exited one second after start: `run.sh` returned 3 on the run lock
   (a live peer `run.sh` was mid-run and correctly refused to be stomped). The
   script then ran `./showstat.sh` **unconditionally**, which renders whatever
   `.last_run.json` points at — run `20260902T184341Z`, an older build — and
   printed `28 PASS, 0 FAIL, 1 POLICY` followed by `DONE`. Read literally that
   log satisfies criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES, the #1
   critical record, on a build it never touched.
   **Fix:** pin `run_id` from `.last_run.json` before the board, require it to
   have MOVED after; if unchanged, print a hard FAIL and emit **no conditions
   table at all**. The log is annotated `RETRACTED — VOID, DO NOT CITE`.

6. **`ls -dt <glob> | head -1` scoring the previous lap.** Chain 87's NDR
   streak harvest did `D=$(ls -dt tests/evidence/board_*_node_death_replay |
   head -1)` and greped `VERDICT` out of `$D`. When a row does not run, that
   glob returns the PREVIOUS lap's directory and its stale `VERDICT PASS` is
   counted as this lap's — a *consecutive streak criterion* could climb on laps
   that never happened. Chain 120 pins the directory before each row and resets
   the streak on any lap that cannot prove it produced a new one.

## The rule this buys

**Before reading any verdict, confirm the step actually ran.** A PASS from an
arm that never injected its fault is worse than a FAIL: a FAIL gets
investigated, a vacuous PASS gets cited to close a record.

Two gate shapes, both cheap:

- **Vacuity gate** (injection harnesses): assert the injection counter/probe is
  non-zero and FAIL loudly when it is zero. `tmpfile_churn_kill.sh` now has one
  (`VACUOUS ARM`); `tmpfile_churn_kill.sh:450` already had the pattern for a
  different arm — copy that shape.
- **Freshness gate** (anything that reads a rendered artifact — a board, an
  evidence directory, a status table): pin the artifact's identity BEFORE the
  step and require it to have changed after. Never let a renderer speak for a
  step whose exit status you did not test.

Symptoms to grep for when auditing old evidence: `installed=1 got=0`,
`P282=0`, `iclus_marked=0`, `entries=0 statted=0`, `order=unknown`,
`relog_holders=[]`, any `got=0 want=N` sitting next to a `VERDICT PASS`, and a
`DONE` whose timestamp is within seconds of the chain's `START`.

## Why it matters beyond one record
The ledger's closed:found ratio has been below 1.0 every month on record
(0.50 / 0.65 / 0.28 — measured again sess480: 81 open of 198, 55 critical).
Some unknown fraction of past "verification" measured nothing, which means the
closed side of that ratio is optimistic, not just the open side. When a
record's closure rests on a chain log, re-read that log for the vacuity
signatures before trusting it.
