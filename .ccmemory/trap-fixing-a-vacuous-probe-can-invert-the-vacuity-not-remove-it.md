---
name: trap-fixing-a-vacuous-probe-can-invert-the-vacuity-not-remove-it
description: TRAP (sess482): the sess481 fix to the vacuous P165 probe produced a probe that can never fire on the population at risk — and the ledger had already…
metadata:
  type: feedback
tags: [probe, evidence, vacuous, d_revalidate, affine, rule6]
---

# Fixing a vacuous probe can invert the vacuity instead of removing it

## What happened

sess481 correctly found `P165-AFFINE-STALE` vacuous: 229,444 of 229,444 lines
carried `d_time=0`, so a test of `d_time != epoch` fired on everything and
discriminated nothing. It then narrowed the predicate to
`d_time && d_time != epoch` and wrote into the ledger that a subsequent
32-node row reporting ZERO of these, against a large `P165-AFFINE-FRESH`
denominator, would be **"the first real evidence the vector does not occur."**

It would not have been. The narrowed predicate is blind to the population the
defect names, for the *same structural reason* the original was vacuous:

- `d_time` has exactly one writer in the tree — the `ret == 1` tail of the
  coordinated validation in `mxfs_drevalidate`.
- The affine fast path **returns before reaching it**.
- Of the three conjuncts selecting that exit, `m_maxagi` is a mount constant,
  the inode's AG is fixed with the inode number (fixed for a positive dentry's
  life), and `m_mxfs_node_slot` is assigned in exactly ONE place
  (`pal/linux/xfs_super.c`, inside `fill_super`). Only the child's in-core
  `S_IFMT` can change.
- So an affine **regular-file** dentry — the whole of the named vector — takes
  that exit for its entire life, is never validated once, and holds
  `d_time == 0` forever.

Volume problem solved (8% of the kernel log removed). Measurement problem
untouched. A run spent on the recorded step would have produced a confident,
plausible, **wrong** negative — which is worse than the original noise,
because a zero reads as a finding.

## The generalisable rule

**A probe fix is not verified by the fix compiling, or by the log getting
quieter. It is verified by demonstrating the new predicate CAN fire on the
population at risk.** Before recording what a future zero would mean, answer:

1. Which population does this exit/branch actually sample?
2. Can every field in the predicate take a discriminating value *in that
   population*? Trace each one to its writer.
3. If a field's writer is unreachable from this code path, the predicate is
   blind there — no matter how sensible it reads.

This is the project's `vacuous-pass` failure in probe form, one level up: the
vacuity moved from the *output* to the *interpretation rule written for the
output*.

## Also learned (RULE-5 ruling, sess482)

My first draft of the argument claimed the narrowed predicate was
*unsatisfiable*. GPT corrected it: `d_time` belongs to the **dentry object**,
not to a particular positive incarnation, so `d_splice_alias`,
negative→positive reincarnation, and `d_move` can all carry a nonzero
`d_time` onto an affine dentry. The defensible claim is **blindness to the
named population**, not impossibility. Overstating it would have handed a
reviewer a true counterexample and discredited a correct finding.

## What replaced it

`mxfs.affine_audit_pct` (0.66.0, default 0): divert a sampled fraction of
blessings into the coordinated validation the exit skips — which already
computes the wanted verdict — and compare. When the field you are testing
cannot see the risk, stop refining the field and go measure the thing itself.
