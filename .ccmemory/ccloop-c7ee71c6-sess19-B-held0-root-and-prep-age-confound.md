---
name: ccloop-c7ee71c6-sess19-B-held0-root-and-prep-age-confound
description: sess19: dropping dir publish measured held=0 (RELFLUSH exemption unsound); storm rate decays with prep age — single-run A/Bs are confounded.
metadata:
  type: project
tags: [ccloop, c7ee71c6, sess19, 32caw, shortform, relflush, methodology, ab-testing]
---

# sess19-B — the dropping publish, and why the A/Bs were wrong

## MEASURED ROOT: the RELFLUSH publication exemption is unsound

`pal/linux/xfs_buf.c` skips a logged DIRECTORY slot written at NL
(`P56-NL-LOGGED-DIR-SKIP`) unless the inode carries `MXFS_IF_DLM_RELFLUSH`.
The exemption's entire justification is the sess14 invariant: the token is set
only across the sanctioned release drain, during which *"the on-disk DLM grant
is still HELD ... so no successor image can exist"*.

I added the ACTUAL grant (`mxfs_v5_dlm_inode_held`) to `P56-DIRWRITE`, ran the
storm, and ordered every node's publishes of one shortform parent by wall-clock
`realns` (`tests/sf_storm_ledger.py`). In EVERY failing round the first
corrupting write is:

    mode=0  rf=1  held=0  comm=kworker/u11:x   <== DROPPED 4 names

**`held=0`** — token set, grant already gone, peers already published. The
premise is false. Later `held=1 comm=mkdir` publishes then carry the poisoned
base forward, which is why names often reappear (some peer republishes a
superset) while the parent's LINK COUNT never does.

Do NOT re-derive this. The stamp is in the ledger analyzer; re-add `held=` to
the probe only for a measurement run — see the perturbation note below.

## THE CONFOUND THAT INVALIDATED THE EARLY A/Bs

The storm's failure rate depends on how long the cluster has run since prep.
One build, one parameter setting, four back-to-back runs:

    run 1 (immediately after prep)   21 of 30 rounds inconsistent
    run 2                             7
    run 3                             7
    run 4                             4

Every A/B I ran as "prep → build A → 1 run" vs "prep → build B → 1 run" is
therefore worthless: the first-run-after-prep penalty swamps the effect.
This retroactively voids these conclusions — they must be re-measured paired:
- `pub_obligation_enforce=1` "no better" (4 vs 5)
- `dir_release_premerge=1` "much worse" (21 vs 9)

`tests/sf_storm_ab.sh <param> <a> <b> [pairs] [rounds] [nodes]` now does it
correctly: no prep, one DISCARDED warm-up, then alternating passes on one
cluster state. INFRA-FAIL passes are excluded, never averaged in as 0.

## RESULT THAT SURVIVES A PAIRED TEST

`dir_nl_require_grant` (v0.11.147 — require `inode_held > 0` before honouring
the RELFLUSH token), paired A/B/A on one cluster state:

    require_grant=1 -> 7      require_grant=0 -> 7      require_grant=1 -> 4

i.e. **no measurable effect**, even though the guard fires ~19x/run. So
blocking that one write does not fix the loss: either another vector dominates,
or the poisoned base is established before this write. The fix is KEPT (it
closes a provably unsound exemption and cannot itself corrupt) but it is NOT
the cure, and must not be reported as one.

## PERTURBATION

This defect is latency-sensitive in BOTH directions — adding work to the drain
raises the loss rate. Two independent instances:
- `dir_release_premerge` (FUA read + 3-way merge + re-log in the drain) fired
  only 11x yet the run showed 21 failing rounds.
- adding `held=` to the hot `P56-DIRWRITE` probe (a DLM lookup on EVERY dir
  publish) gave 23.
Both are consistent with the root: the drain's write RACES peers who have
already published, so anything that delays the drain widens the window. Keep
diagnostic work OFF the drain path; sample it, don't instrument it inline.

## Params added this session (all A/B levers)
- `mxfs.dir_rebase_verguard` (default 1) — P178, refuse a shortform rebase from
  a platter image older than in-core (`di_changecount < i_version`).
- `mxfs.dir_nl_require_grant` (default 1) — the held>0 requirement above.
- `mxfs.dir_release_premerge` (default 0) — REFUTED-as-measured, kept as lever.
- `mxfs.nlink_ledger` (default 0) — P180-NLB/NLR/NLW link-count ledger.
- P181-FORK-TORN tripwire in `xfs_trans_log_inode` (always on, capped 20 +
  dump_stack) — has NOT yet caught the test6 mount-killing torn fork; that
  event has not recurred since.
