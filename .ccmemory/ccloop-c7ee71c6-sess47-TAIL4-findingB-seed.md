---
name: ccloop-c7ee71c6-sess47-TAIL4-findingB-seed
description: sess47 findingB seed: xfs_inactive authority guard uses NON-coherent mxfs_dbg_disk_di_mode (xfs_inode.c:4641) while nlink is coherent (4658); coheren…
metadata:
  type: project
---

# Finding B opener (foreign-zombie authority guards) — seeded

xfs_inactive's multi-node nlink==0 guard block:
- line 4641: `mxfs_dmode = mxfs_dbg_disk_di_mode(mp, ...)` — **raw variant** (FUA/plain read; the family exposed to stale/pre-write images).
- line 4658: `mxfs_dbg_disk_di_nlink_coherent(...)` — coherent variant for nlink.
- line 1926 (different call site): `mxfs_dbg_disk_di_mode_coherent` EXISTS and is already used elsewhere (defined xfs_mxfs_dlm.c:32911, EXPORTed).

Hypothesis: the mode read at 4641 serving a stale LIVE image (mode!=0 for a peer-freed inode) lets a lu=0/au=0/ub=-1 foreign zombie into destructive inactivation (the test32 chain's finding B). RULE-4: instrument first — print raw vs coherent mode when they DIVERGE at 4641 (one extra read only when raw says live and gen/nlink smell foreign), correlate with any -117-class recurrence; if proven, switch 4641 to the coherent variant (mirror of the nlink choice made at 4658 — check that call's commit rationale in git blame/awareness first for why mode was left raw: possibly cost — coherent likely forces a flush/FUA fence).

Everything else: see TAIL3 (0.11.380 state + queue), TAIL2 (379), the corrected variant decode (TAIL-372-variant-gate-miss), ADDENDUM (delwri fossil hunt), END memory (session scorecard). Rig: 0.11.380, 32/32, green, 2 clean aged soak cycles.
