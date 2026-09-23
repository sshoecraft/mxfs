---
name: trap-timeout-around-run-sh-piped-to-tail-kills-the-reader-not-the-run-and-orphans-the-cluster-lock
description: TRAP (sess570): `timeout N ./run.sh ... | tail` kills the pipeline reader, not run.sh; the tool reports exit 0 while the board keeps running and its…
metadata:
  type: feedback
tags: [trap, harness, run.sh, sess570, rig, mis-reporting]
---

# `timeout N ./run.sh … | tail` does not stop the board

## What happened

    timeout 1000 ./run.sh 2 tcp 2>&1 | tail -70

reported **exit code 0** and the session treated the board as finished. It was
not. `showstat` showed 7 rows still PENDING, and `.last_run.json` still named
the *previous* run. The `run.sh` process tree was alive and still executing
rows — rows 22 and 23 completed between two consecutive checks.

`timeout` wrapped `run.sh`, but the pipeline's exit status is `tail`'s, and
`run.sh` survived the signal. So the wrapper detached the reader from a run that
kept going.

## The second-order damage

The orphan holds `/tmp/mxfs_run.lock`. Every later `./run.sh` refuses:

    ERROR: another run.sh holds /tmp/mxfs_run.lock — refusing to stomp its cluster

and exits **3 without creating an evidence directory**. A driver that then reads
"the newest `tests/evidence/run_<test>_*` directory" re-scores the PREVIOUS
lap's artifacts — four A/B laps in a row "reproduced" a failure not one of them
had run, all reporting the same stale evidence path.

## The rules

- **Never pipe a `run.sh` invocation through `tail` under `timeout`.** Redirect
  to a file and read the file: `timeout N ./run.sh 2 tcp > "$LOG" 2>&1`.
- **A run is finished when its own state says so**, not when the wrapper
  returns: `.last_run.json` names the run id, and `showstat.sh <n> <dlm>` shows
  zero PENDING rows. Check one of those before concluding.
- **If the lock is held, find out whether the holder is progressing before
  killing it.** `fuser` on the lock names the PIDs; `/proc/<pid>/stat` field 3
  gives the state and `/proc/<pid>/comm` the name (both safe — `cmdline` and
  `maps` are not, and `pgrep`/`ps -e` are banned). A holder that is still
  completing rows is doing the work you wanted; killing `run.sh` mid-flight
  leaks the module refcount and breaks the next prep.
- **Any driver that runs a harness must require a NEW evidence directory** and
  treat "same directory as before the lap" as a lap that did not run.
