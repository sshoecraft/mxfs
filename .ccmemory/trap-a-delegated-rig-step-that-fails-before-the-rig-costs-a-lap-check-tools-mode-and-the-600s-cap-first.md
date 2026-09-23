---
name: trap-a-delegated-rig-step-that-fails-before-the-rig-costs-a-lap-check-tools-mode-and-the-600s-cap-first
description: TRAP (sess603): a board aborted in prep because tools/mkfs_mxfs was absent (make tools), two harness arms were no-ops because Write leaves no +x, and…
metadata:
  type: feedback
tags: [rig, harness, delegation, traps]
---

# A delegated rig step that fails before it reaches the rig still costs the lap

Three ways one session lost rig laps to things that had nothing to do with MXFS,
each caught only when the rig-runner's report came back.

1. **The userspace tools were not built.** `./run.sh 2 tcp` aborted at
   `PREP FAIL (mkfs): FS_PREP_FAIL: mkfs tool not found/executable at
   /src/mxfs/tools/mkfs_mxfs`. Only `caw_verify` was present; mkfs_mxfs, chk_mxfs,
   resize_mxfs and fua_verify were gone (they are build products, not tracked).
   `make tools` rebuilds them in seconds. Before a board: `ls tools/mkfs_mxfs tools/chk_mxfs`.

2. **A harness written with the Write tool has mode 664.** Both arms of a new
   harness returned `Permission denied`, rc=126, after the fleet had been prepped for
   them; the deploy and the re-prep bracketing the two no-ops were the whole cost.
   After writing any script: `chmod 775` and `bash -n` before it goes to the rig.

3. **The Bash tool auto-backgrounds a foreground command at 600 s**, and a
   rig-runner that hits that returns "waiting for the background task" and ends,
   while the board keeps running on the host as an orphan of the agent (the flock in
   /tmp/mxfs_run.lock still protects it). A board is ~13 min plus prep, so a single
   `./run.sh 2 tcp` call always trips this. Either split the wait (a second agent
   blocking on `/proc/<run.sh pid>/comm`), or accept that the first agent's report is
   partial and read the log afterwards. Never re-launch: the lock holder is alive.

Also: the state hook's "read it with ./showstat.sh" is stale — the reader is
`python3 tools/criteria.py 2 tcp`, whose FLAKY marks are cross-run (last 11 runs at
that configuration), not rows of the board just run.
