---
name: trap-a-lap-that-exercises-the-new-refusal-proves-nothing-unless-it-captures-the-predicates-the-deleted-branch-would-have-read
description: TRAP (Astra s86): "the key was absent, so the old build would have minted kind 16" is unsupported unless the lap records the ledger/boundary values t…
metadata:
  type: feedback
tags: [regression-evidence, fencing, counterfactual, ruling]
---

# Proving a deleted branch is gone needs its antecedent, not just its consequent

**The claim that fails.** A branch was deleted because it minted a fence kind
from bookkeeping instead of from a completed target operation. The obvious lap
is: reach the state where that branch used to fire, and show the build now
refuses. The obvious grading is: "the old code would have answered this absent
key from ledger FENCED or RETIRED and minted kind 16, so this refusal proves
the branch is gone."

**Why it is unsupported.** The deleted branch had a *guard*, and the lap only
established the situation, not the guard. If the ledger lookup would have
returned neither FENCED nor RETIRED, and no succession predicate matched, the
OLD build would have refused this lap too — by falling off the end of the same
chain. The lap then measures the new refusal path without ever reproducing the
defect, and reads as a regression test for something it never touched.

**What to do instead.** Capture, in the lap's own evidence, the values the
deleted branches examined at the moment of the decision: the ledger entry's
state for that key, the boot/nexus predicate, whatever else gated them. Then
the counterfactual is a statement about recorded inputs rather than about the
outcome.

**The second half, equally easy to miss.** One lap reaches one antecedent. If
three branches were deleted, the honest coverage argument is: the lap measures
the antecedent(s) it hit; INSPECTION establishes that the path now refuses
unconditionally whatever those predicates say; predicate-level tests may cover
the rest. "This lap measured all three deleted branches" is false and will be
read as coverage by whoever disposes of the record.

**Related, same ruling.** Assert the absence of AUTHORITY, not the absence of
the retired class — substituting a different unsupported kind, or a spuriously
"proven" one, preserves the defect exactly. And a post-hoc disk read cannot
exclude "minted, used, then overwritten", nor can a missing log line exclude
unlogged publication: instrument the minting and publication sites themselves.

Full ruling: `docs/rulings/bootstrap-takeover-closure-and-the-recovery-dead-end.md`.
