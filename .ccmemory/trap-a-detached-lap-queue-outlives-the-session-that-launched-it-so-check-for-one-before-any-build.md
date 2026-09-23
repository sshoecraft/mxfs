---
name: trap-a-detached-lap-queue-outlives-the-session-that-launched-it-so-check-for-one-before-any-build
description: TRAP (s138): tests/lap_queue.sh is launched with nohup setsid, so it survives the session that started it; a new session that reads a handoff saying…
metadata:
  type: feedback
tags: [rig, build, handoff, lap_queue]
---

# A detached lap queue outlives the session that launched it

`tests/lap_queue.sh` is documented to be launched as

    nohup setsid tests/lap_queue.sh <label> <queue-file> > ... 2>&1 &

`setsid` puts it in its own session and `nohup` detaches it from the terminal, so
**it keeps running after the Claude Code session that started it has ended.** A
relay handoff that says "7 of 11 laps done" is a snapshot, not a stop.

## What it cost

s138 opened, read a handoff describing an 11-lap queue as the *previous*
session's work, and started `make modules` as its first action. The queue was in
fact still live — lap 8 had started 41 s earlier. Every lap re-preps the fleet
and deploys `/src/mxfs/mxfs.ko`, so a relink mid-queue splits the sweep across
two srcversions and silently invalidates every later lap. Nothing was lost only
because the link had not happened yet when the build was stopped.

## The check, before any `make`

    date -u +%FT%TZ
    tail -3 tests/evidence/lapq_<label>.log        # a QUEUE DONE line means finished
    for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); \
        case "$c" in *lap_queue*|*run.sh*) echo "$p $c";; esac; done

Read `/proc/*/comm`, never `pgrep -f` / `ps aux` — those take every process's
`mmap_lock` and wedge this host unkillably.

A queue log whose last line is `QUEUE lap=N starting` and NOT `QUEUE lap=N rc=`
means lap N is in flight right now.

## Two facts that bound the damage

- `run.sh` does **not** build. It deploys whatever `mxfs.ko` is in the tree, so
  recompiled `.o` files are inert until something relinks. Stopping a build
  before the link leaves the deployed module untouched.
- The queue file itself is read in full into an array before the first lap runs,
  so editing the queue file mid-run changes nothing. Editing a *harness script*
  that is currently executing is the dangerous one — bash re-reads by byte
  offset.
