---
name: trap-closing-a-defect-on-one-call-site-leaves-the-class-open-368-to-5
description: TRAP (sess573): D-0904 was closed FIXED AND VERIFIED after adding sole_survivor() at ONE call site; the tree has ~369 is_single_node sites and 5 sole…
metadata:
  type: feedback
tags: [rule6, sole-survivor, class-vs-instance, audit, D-0904, D-0949]
---

# A defect closed on one call site when the bug was the predicate

sess573. `D-SURVIVOR-SINGLE-NODE-BYPASS-SERVES-STALE-VIEW-AFTER-PEER-DEATH-0904`
was closed **FIXED AND VERIFIED** on 2026-09-04. The fix was correct: it added a
`mxfs_v5_dlm_sole_survivor()` check at `mxfs_dlm_ilock_begin`
(`xfs/xfs_mxfs_dlm.c:32662`), rig-verified on a 2-node TCP death chain.

The *defect* was that `mxfs_v5_dlm_is_single_node()` is dynamic membership, so
every "we're standalone, take the cheap path" decision is wrong for the sole
survivor of a peer's death. Census on 0.75.124:

| predicate | occurrences | real calls |
|---|---|---|
| `mxfs_v5_dlm_is_single_node` | 390 | ~369 |
| `mxfs_v5_dlm_sole_survivor` | 8 | 5 |

One call site was fixed. **~364 were never looked at.** Nine months of sessions
then read the ledger and saw the class as handled, because the record said
FIXED AND VERIFIED and the code carried its name in a comment.

Two of the unaudited sites sit on the exact path a later campaign was stuck on:
- `xfs_ialloc.c:4238` `xfs_difree_finobt` — the *identical* chunk-delete guard
  as the inobt one; fixing only one leaves the two btrees disagreeing.
- `xfs_ialloc.c:3078` `mxfs_dialloc_two_phase` — the D-0351/D-0946 candidate
  validator is **skipped entirely** when single-node, i.e. the platter-liveness
  gate switches off precisely in the post-death window.

## The rule to apply

When a defect's root is **a predicate, a helper, or an idiom** rather than a
line, closing it requires a **census of every use**, not a fix at the reported
site. Before writing FIXED AND VERIFIED, ask: *is the thing I fixed the bug, or
one instance of it?* If the answer is "one instance", the record closes only
when the sweep is done — or a class-level record stays open naming the census.

Cheap check that would have caught this: `grep -rc` both the unsafe and the safe
predicate and compare the counts. A ratio like 369:5 is the finding.

## Related

`d0948-guard-conditioned-on-dynamic-membership-is-off-for-the-sole-survivor`
(the D-0949 filing) carries the full site list.
