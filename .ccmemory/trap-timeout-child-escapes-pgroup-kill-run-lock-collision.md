---
name: trap-timeout-child-escapes-pgroup-kill-run-lock-collision
description: TRAP (sess468): `kill -- -<pgid>` on a setsid chain does NOT kill a `timeout N ./run.sh` child — GNU timeout puts the command in its own process grou…
metadata:
  type: feedback
tags: [trap, sess468, timeout, pgroup, run.lock, chain-kill]
---

# Trap: killing a chain's process group leaves its `timeout` children alive

sess468, 10:50Z: chain 98b (setsid nohup) was stopped with `kill -TERM -- -2835208; kill -KILL -- -2835208`
(its pgid = its pid). The chain, its `lap()` shells and `timeout` itself died, but the
`./run.sh 32 caw crash_consistency` that `timeout 160` had started kept running: GNU `timeout`
runs the command in its OWN process group (so it can signal the whole command tree without
hitting itself), so a group kill aimed at the chain never reaches it.

Consequence: the orphaned run.sh (pid 2977516, plus its ssh fan-out) still held
`/tmp/mxfs_run.lock` when chain 99 started 19 s later; chain 99's `prep_joiner` failed
`rc=3 'another run.sh holds /tmp/mxfs_run.lock'` and the chain went on to its joiner arm on
the un-prepped (but mounted, same-sv) fleet.

Rules:
- After killing a chain, ALSO kill its run.sh: `for p in $(tools/mxfs_pgrep.sh 'run.sh'); do ...`
  (never `pgrep -f` host-locally — RULE 2c), or check `fuser -v /tmp/mxfs_run.lock` is empty
  before appending a DONE to a gate log.
- Better: append the DONE to the gate only once the lock is free; the gate poll is 30 s.
- `tools/mxfs_pgrep.sh '<pattern>'` also matches the CALLING shell's cmdline (sess467 exit 144):
  build the pattern at runtime (A=chain9; "${A}8") and skip cmdlines containing 'snapshot'.
