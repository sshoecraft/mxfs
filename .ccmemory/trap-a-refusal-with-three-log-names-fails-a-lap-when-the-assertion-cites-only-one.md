---
name: trap-a-refusal-with-three-log-names-fails-a-lap-when-the-assertion-cites-only-one
description: TRAP (s75b): both file probes returned a real EIO while P240-RBLK-EIO-ABORT stood at 0 — the entry gate refused them first under a different name. Co…
metadata:
  type: feedback
tags: [harness, measurement-integrity, dlm]
---

# One mechanism, three log lines — cite all of them or the lap lies

The recovery-blocked refusal in `dlm/dlm.c` reaches a caller by three different
printed names, depending on which question answered first:

- `P240-RBLK-EIO-ABORT` — the acquire path's own explicit abort
  (`xfs/xfs_mxfs_dlm.c`);
- `P-RBLK-COVERS-DEAD-MASTER` — the entry gate, when the resource is *mastered*
  by the blocked node;
- `P-RBLK-COVERS-DEAD-HOLDER` — the entry gate, when it is merely *held* by it.

Which one fires depends on which node masters that inode, and **that changes
from lap to lap** — `dlm.c` says so in its own comment.

Measured, lap `s75b`: two of three probes returned a genuine
`Input/output error` to the caller, and the assertion
`P240-RBLK-EIO-ABORT >= 1` read **0** and printed a FAIL. The mechanism worked
perfectly; the harness named one of its three mouths.

**Count every name the mechanism can print, sum them for the assertion, and
report the breakdown** so the evidence says which path did the work:

    --- the recovery-blocked refusals on test1: acquire-abort=0 \
        entry-gate-dead-master=2 entry-gate-dead-holder=0

The general form: when a single mechanism has several printed identities, an
assertion that cites one of them is over-specified, and it fails in exactly the
laps where the mechanism took its other branch — which look like regressions
and are not.
