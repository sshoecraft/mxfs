---
name: trap-a-closure-condition-written-into-a-records-next-step-can-contradict-the-banked-ruling-read-the-ruling-before-disposing
description: TRAP (s73→s74, D-FENCE-CRASH-MATRIX-UNTESTED): the record's next-step said "closure = both arms' six cuts"; the s68 ruling says cuts 1-6 are a first…
metadata:
  type: feedback
---

# A record's own next-step is not the disposition standard; the banked ruling is

Session 73 wrote into `D-FENCE-CRASH-MATRIX-UNTESTED`'s next-step: "Closure of THIS
record = both arms' six cuts measured with their predicted durable state and recovery
outcome on this target class." Session 74 was about to remove the record on the
silent-victim sweep's 6/6 PASS on that sentence alone.

`docs/rulings/fence-crash-matrix-cuts.md` (session 68 consult) says in its first
section: "Cuts 1-6 on the prover are accepted as a first tranche, never as closure of
the record", and lists the crash points still missing (in-flight P&A variants, partial
snapshot/seal, partial replay, non-durable stage advances, lost-ack zero, competing
owners, partition/reconnect, APTPL target restart). The s72 ruling that added the
silent arm "extends fence-crash-matrix-cuts.md; it replaces nothing there."

Removing on the next-step text would have been redefining the requirement after the
measurement — exactly what the zero-accepted-defects rule forbids.

## The rule for a disposition

Before `defects.py remove`, read every ruling the record's `found`/`evidence` names
(the `docs/rulings/*.md` it cites) and check the closure claim against the ruling's
own "what counts as closure" sentence. A next-step is the previous session's plan for
the next lap; it inherits nothing from the ruling and may have been written for the
lap's obligation ("both arms of the s72 ruling") rather than the record's.

Measured outcome: the fence record was UPDATED (both arms 12/12 PASS recorded, the
remaining matrix restated from the ruling) instead of removed.
