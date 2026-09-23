---
name: technique-before-believing-a-record-that-says-a-leg-refuses-with-no-fallback-check-whether-the-refusal-mutates-the-verdict
description: TECHNIQUE (s118): a record predicted a hard refusal with no fallback; the refusing function returns without touching the verdict, so control falls th…
metadata:
  type: feedback
---

## The claim and what was actually true

`D-FENCE-CRASH-MATRIX-UNTESTED`'s next step said cut 1 would fail at
`P238-BOOTSUCC-NO-RETIRE-BASIS` because `v5_boot_succession_consume` asks only
`mxfs_scsipr_retire_proof()`, which answers `NONE` since 0.89.16, "so
`P238-BOOTSUCC-NO-RETIRE-BASIS` still refuses **with no LU-reset leg to fall
back on**."

That last clause was wrong, and it was decidable by reading two things:

1. **How many call sites the refusing function has.** `grep -n` showed exactly
   one for `v5_boot_succession_consume` and one for `v5_self_succession_consume`
   (`dlm/v5_mount.c:9917` and `:9912`).
2. **Whether the refusal mutates the verdict it was asked about.** Both return
   *without assigning* `fres->kind`. So the verdict stays
   `MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN`, which is the exact predicate of the
   NEXT branch (`dlm/v5_mount.c:9936`) — and that branch's `gbasis == NONE` arm
   is where the witnessed LU reset lives.

The lap confirmed it: `BOOTSUCC=0`, no `P238-BOOTSUCC-*` for the victim at all,
and both victims certified `LU_RESET_WITNESSED_V1`.

## The general move

A "refuses, full stop" claim about a chain of consumers is a claim about
CONTROL FLOW, not about the refusal. Two greps settle it:

- how many call sites the refusing function has, and
- whether its refusal path writes the value the following branches test.

A refusal that only LOGS is a fall-through, not a stop. Sequential
`if (verdict == X) try_consumer_N(&verdict);` chains are the common shape, and
each consumer's refusal hands the case to the next one silently.

## Why it mattered

The record had turned that wrong clause into a whole prescribed programme — "the
boot-succession consumer needs the same witnessed leg the prover already has,
which is an implementation task" — for a leg that was already reachable. Reading
the two greps before running the lap cost nothing; believing the record would
have cost an unnecessary patch to the fencing path.

Related, same record, one session earlier:
`trap-a-records-next-step-can-declare-a-route-closed-on-reasoning-a-later-version-made-obsolete-by-building-it-another-way`.
The same next-step field has now been wrong twice in the same direction — it
over-reports what is closed. Re-derive its reachability claims from the tree.
