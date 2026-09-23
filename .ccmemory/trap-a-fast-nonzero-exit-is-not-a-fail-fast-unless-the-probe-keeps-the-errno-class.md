---
name: trap-a-fast-nonzero-exit-is-not-a-fail-fast-unless-the-probe-keeps-the-errno-class
description: TRAP (s74j/s75): `stat … 2>&1 >/dev/null; echo RC=$?` keeps only the status. rc=1 in 0s is ENOENT as readily as EIO — and ENOENT means the probe neve…
metadata:
  type: feedback
tags: [harness, measurement-integrity, vacuity]
---

# "It failed quickly" is not a fail-fast

A hang fix is verified by running the operation that hung, bounded, and showing
it now returns. The trap is throwing away *why* it returned.

`timeout 30 stat "$MNT/$d" > /dev/null 2>&1; echo STAT_RC=$?` keeps a single
bit. **ENOENT is also `rc=1`, and it is also instant** — and it means the
operation never reached the frozen grant the check claims to be about. The
assertion "returned in 0 s, so it failed fast" is then unfalsifiable: a probe
that touched nothing passes it.

Measured, lap `s74j` (`tests/fence_lost_response.sh`): the probe returned
`rc=1` in **0 s** with `P240-RBLK-EIO-ABORT = 0` — the acquire path's explicit
abort never fired, so the fast failure came from somewhere else entirely. The
same probe on an earlier lap had a real `P240-RBLK-EIO-ABORT ino=8388742
comm=stat`. Nothing in the captured evidence distinguished the two.

## What the probe has to keep

- the **errno class**, taken from stderr *before* it is discarded:
  `e=$(cmd 2>&1 >/dev/null); rc=$?` then a `case` on `*'Input/output error'*`,
  `*'No such file'*`, `*'Structure needs cleaning'*`, empty;
- the **verbatim stderr** in the evidence directory, so the classification can
  be audited later;
- a **corroborating kernel line** — the mechanism that was supposed to produce
  the error — so "the operation failed with EIO" and "the gate fired" are two
  independent facts, not one restated;
- and a named outcome for "the probe never reached the state", which is an
  **ABORT** about the harness, never a FAIL about the filesystem.

More than one target helps: probe the mount root, the directory the victim
created, and the file the victim's writer is appending to when it is fenced.
Which of them actually needs a frozen grant varies per lap, because which node
masters a given inode varies per lap.
