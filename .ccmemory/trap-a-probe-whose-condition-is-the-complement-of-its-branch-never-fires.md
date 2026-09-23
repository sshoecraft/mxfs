---
name: trap-a-probe-whose-condition-is-the-complement-of-its-branch-never-fires
description: TRAP (sess573): P103-CHUNKFREE sat inside a branch requiring NOT-multi-node and itself required multi-node — complements, so it never printed once in…
metadata:
  type: feedback
tags: [instrumentation, rule4, xfs_ialloc, unreachable-probe]
---

# A probe guarded by the complement of its own branch is dead code that looks like coverage

sess573, `xfs/libxfs/xfs_ialloc.c` `xfs_difree_inobt`.

The chunk-delete branch is entered under:

    !(mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))

i.e. `!D || S` — **not multi-node**. Inside it sat:

    if (pag_mount(pag)->m_mxfs_dlm &&
        !mxfs_v5_dlm_is_single_node(pag_mount(pag)->m_mxfs_dlm))
            pr_warn("mxfs: P103-CHUNKFREE ...")

i.e. `D && !S` — **multi-node**. That is the exact complement of the enclosing
condition, so the probe could not print. Every inode-chunk deletion the
filesystem ever performed was silent, and the path shows up in **no** evidence
directory anywhere in the tree.

## Why it fooled everyone (me included, at first)

The probe *reads* as multi-node-only instrumentation, and the comment above it
describes a real multi-node hazard (`P103-CHUNKFREE ... bnobt double-free`).
Both halves reference multi-node, so eyes slide over it. The condition is only
wrong relative to the branch it sits in — which is 30 lines up.

## The generalisable check

Before trusting "this path is quiet, so it doesn't happen": **evaluate the
probe's guard conjoined with every enclosing guard.** If the conjunction is
unsatisfiable, silence means nothing. This is the same failure family as
`trap-a-silent-instrument-and-a-clean-system-are-the-same-observation`
(sess571) — but worse, because here the instrument is unsatisfiable by
construction rather than merely unexercised, so no workload could ever have
fired it.

Cheap standing habit: a probe that has **never** appeared in any captured
evidence, despite the path plausibly running, is a candidate for this bug.
Grep the evidence tree for the tag before believing a zero.
