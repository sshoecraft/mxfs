---
name: trap-a-vacuity-gate-can-count-the-probe-that-fires-only-when-the-thing-it-requires-did-not-happen
description: TRAP (s99): authtail's "did this mount replay a foreign slice?" gate counted P163-RECOVERED — the monitor's NO-REPLAY path — so 4 laps read VACUOUS w…
metadata:
  type: feedback
tags: [harness, measurement-integrity, replay, probe-naming]
---

# A vacuity gate counted the probe that fires only when its precondition FAILED

`tests/authtail_mount_unwind.sh` refuses to grade a lap unless the refused
mount actually foreign-replayed a slice — correct, because with nothing
recovered the unwind has nothing to push and a zero says nothing.

It implemented that as `cnt journal.txt 'P163-RECOVERED'`.

`P163-RECOVERED` (dlm/disklock.c:3248) is the monitor's completion path for
recovery that ran with **NO replay**. The replay path prints
`P163-RECOVERY-COMPLETE` and `MXFS: foreign replay of slot N complete`
(xfs/xfs_log.c:1599). The two are mutually exclusive, so the gate passed
exactly when the precondition was false and failed whenever it held.

Four consecutive laps (s97, s98, s100, s101) reported `RESULT: VACUOUS ... the
refused mount REPLAYED NO FOREIGN SLICE` while their own journals carried
`foreign replay of slot 1 complete`, `P163-RECOVERY-COMPLETE` and a barrier
line reading `replayed=1 published=0x2`. Three release-gate records depend on
that harness, and it could never have graded any of them.

## Why grepping for the string existing is not enough

The string DOES exist in the tree — 10 occurrences of `P163-RECOVERED` — so a
"does the kernel print this?" check passes. What was wrong was the *polarity*:
a family of sibling probes (`P163-RECOVERED`, `P163-RECOVERY-COMPLETE`,
`P163-RECOVERY-PENDING`, `P163-COMPLETE-NOPEND`) share a prefix and differ
only in which branch reached them.

## What to do instead

- For a precondition gate, count the probe emitted by the **thing you require
  to have happened**, and read that probe's own source line to confirm which
  branch prints it. A prefix match across a probe family is not a match.
- Prefer the line that names the event in the subsystem's own words
  (`foreign replay of slot N complete`) over a `P<number>-` tag: the tag is
  easy to confuse with its siblings, the sentence is not.
- A harness that keeps returning VACUOUS / SKIP / "nothing to measure" on a
  path you have independent evidence DID run is a harness bug until proven
  otherwise. Cross-check the raw journal against the gate's own predicate
  before concluding the workload is wrong.
