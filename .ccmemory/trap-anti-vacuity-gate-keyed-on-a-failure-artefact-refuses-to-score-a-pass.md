---
name: trap-anti-vacuity-gate-keyed-on-a-failure-artefact-refuses-to-score-a-pass
description: TRAP (sess483): chain 126's vacuity gate keyed "did it run?" on an evidence directory only written on FAILURE — so it reported the passing half of it…
metadata:
  type: feedback
tags: [sess483, sess480, vacuity, harness, crash-consistency, measurement]
---

# A vacuity gate keyed on a failure artefact cannot score a pass

This project's dominant evidence failure is the **vacuous PASS** — a harness
reporting success for work never performed. The correct response has been to
add gates that refuse to score unless the step provably ran. sess480's chain
126 did that. Its gate then destroyed the experiment's answer.

## What happened

Chain 126 was the discriminating A/B for the failing `crash_consistency` board
row: same build, alternating legs minutes apart, one shared directory versus
`CC_PRIVATE=1` per-node directories. Its own header states the prediction —
*"If the private legs pass … the shared-directory inode is the cause and
D-32NODE-SHARED-DIR-CREATE-PACE owns the crash_consistency row outright."*

Its freshness check was:

```bash
pre=$(ls -dt tests/evidence/run_crash_consistency_* | head -1)
... run the row ...
post=$(ls -dt tests/evidence/run_crash_consistency_* | head -1)
if [ "$post" = "$pre" ]; then
  echo "LEG ... NOT SCORED: the row produced no new evidence directory"
  continue
fi
```

**`tests/evidence/run_crash_consistency_*` is written when the row FAILS.** A
passing row writes none. So the gate is structurally incapable of scoring a
pass — and the private legs are exactly the ones expected to pass.

Both private laps were discarded. The captured leg output, unread until
sess483, said:

```
lap1 private  run_id=20260904T023018Z  PASS 18s/90s  nodes_pass=32/32  checks=204 passed=204 notrun=0
lap2 private  run_id=20260904T023746Z  PASS 19s/90s  nodes_pass=32/32  checks=204 passed=204 notrun=0
lap1 shared                            FAIL 90s/90s  nodes_pass=0/32   61 of 204,  143 notrun
lap2 shared                            FAIL 90s/90s  nodes_pass=0/32   152 of 204,  52 notrun
```

The answer was sitting in `tests/evidence/sess480_cc_private_s480l/` the whole
time, and the chain's "reading" section printed the criteria for interpreting
a result it had refused to look at.

## The rule

**A liveness gate must key on an artefact the step produces in EVERY outcome,
not one it produces only when it fails.** Ask: *does this key exist when the
result is the good one?* If not, the gate is a pass-suppressor.

Here the right key was already in the leg's own captured output: run.sh prints
`=== run @ 32/caw (run_id=<stamp>) ===` on every invocation, pass or fail. Fixed
in `tests/sess480_chain126_cc_private_barrier.sh` (sess483): score on a fresh
`run_id` plus the presence of a `nodes_pass` verdict row; use the evidence
directory only for the per-node parked/straggler detail, whose absence now
prints "nothing parked" instead of refusing the leg.

## Corollary worth carrying

Anti-vacuity gates are still right — but they are code, and they need the same
falsification discipline as the thing they guard. Before trusting a gate, ask
what it does on the OUTCOME YOU ARE HOPING FOR. A gate only ever exercised
against failures has never been tested.

## What the recovered result establishes

`D-32NODE-SHARED-DIR-CREATE-PACE` (raised **major → critical**) owns the
`crash_consistency` row. The fleet-wide barrier converges fine in the private
shape, so `D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401` loses that row as
its evidence — without being disproved on its own.
