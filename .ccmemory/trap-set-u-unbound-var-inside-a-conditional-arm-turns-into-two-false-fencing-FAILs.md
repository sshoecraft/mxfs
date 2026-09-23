---
name: trap-set-u-unbound-var-inside-a-conditional-arm-turns-into-two-false-fencing-FAILs
description: TRAP (sess563): tcp_death_replay.sh had no MXFS_DEV default; set -u killed the PR-state read mid-arm, and two reservation assertions then FAILed agai…
metadata:
  type: feedback
tags: [trap, harness, evidence-integrity, vacuous-evidence]
---

# TRAP: an unbound variable inside a conditional arm reads as a fencing regression

## What happened (sess563, s583neg, 2026-09-09)
`tests/tcp_death_replay.sh` documents a default for `MXFS_DEV` in its own Env
header and **never had one**. All four uses sit inside conditional arms, so
under `set -u` a direct invocation did not fail at the top. It died partway
through the sole-survivor gate arm, at line 876 — the one line that reads the
target's PR state:

    tests/tcp_death_replay.sh: line 876: MXFS_DEV: unbound variable
      INFO PR state on test1 after restore:
      FAIL exactly one registration (the survivor's) after the restore got= want=1
      FAIL WE-AR reservation in force after the restore got=0 want=1

`prstate` was empty, and both assertions compared against the empty string.

## Why it matters more than a normal harness bug
Those two lines are about the persistent reservation that **all** of MXFS's
fencing rests on, and they were produced by an unset shell variable on a run
whose gate had certified, restored, and published `P163-RECOVERY-COMPLETE`
cleanly, with 327/327 files verifying and zero bad or missing. Read at face
value they say "the reservation is gone after the restore" — a critical fencing
regression that the run never observed.

## The generalisable lesson
`ck "<claim>" "$(measurement)" "expected"` cannot distinguish **"the thing is
broken"** from **"I could not look at the thing"**. When the measurement can
come back empty, assert on the emptiness FIRST and report it as a failed
measurement that names itself a harness fault. Otherwise every such gap enters
the record as a defect in whatever the assertion was about.

## Both halves fixed in 0.75.89
1. `: "${MXFS_DEV:=<QNAP by-path>}"` at the top, the same default every sibling
   harness carries.
2. The PR-state block refuses to compare an empty reading and prints
   "the two reservation assertions below were NOT measured (this is a harness
   fault, not a fencing fault; do not diagnose the reservation from it)".

## Check this pattern elsewhere
Any `set -u` harness whose env vars are only read inside optional arms has the
same shape: it will pass for months and then die inside the one arm that
matters, on the day that arm first runs.
