---
name: trap-a-selection-step-keyed-on-a-cumulative-dmesg-count-picks-the-previous-runs-target
description: TRAP: a harness that CHOOSES its target from an unscoped dmesg count inherits the previous run's hits, aims the fault at the wrong object, and passes…
metadata:
  type: feedback
tags: [harness, dmesg, vacuity, measurement-integrity]
---

# A cumulative dmesg count is worse in a SELECTION step than in a verdict

The known form of this trap is a verdict counted over the whole kernel ring.
There is a nastier form: a harness that **chooses what to test** from such a
count. Then the run is not merely mis-scored, it is aimed at the wrong object,
and every downstream check passes honestly about something irrelevant.

## What happened (sess578, D-0912)

`tests/tcp_lockreq_blackhole.sh` picks a target inode by arming a fault for a
candidate and asking whether the fault's probe fired — the probe only fires on
the remote-master send path, so it *is* the test for "is this inode remotely
mastered from here". It counted with a bare `dmesg | grep -ac 'P912-DROP-LOCKREQ
.* ino=131 '`.

Run s578b left 15 such lines in the ring. A module swap between runs does NOT
clear the ring. Run s578c therefore read 15 hits for ino 131 before touching
anything, selected it, and armed the fault for an inode that was **locally
mastered in that cluster incarnation** — so the fault could not fire. The read
went down an ordinary path and succeeded. The harness printed **nine PASSes**,
including its own anti-vacuity gate ("the drop instrument fired"), on a run that
never went near the code under test.

Two things made it survive: the count was cumulative, and the vacuity gate was
`count >= 1` rather than `count > baseline-taken-just-before-the-measurement`.

## What to do

- Mark the kernel log at the start of the run and scope **every** count to it.
  `DM="dmesg | awk '/$MARK/{f=1} f'"` composed locally and interpolated into the
  remote command needs no `$` escaping, unlike the `sed -n "/$MARK/,\$p"` idiom.
- A vacuity gate compares against a **baseline sampled immediately before the
  measurement**, not against zero. The setup phase of a harness often fires the
  same probe.
- Mastership of a DLM resource is a hash over the resource id and the active
  node set: it **changes with every cluster formation**. Any harness that needs
  a remotely-mastered object must re-discover it each run and must not cache the
  inode number across a module swap.

## The second bug in the same loop

`while read -r idx ino md5; do ... ssh ... done < candidates.txt` — the ssh
inside the loop reads stdin and **swallows the remaining candidates**, so the
search gave up after one. Use `done 3< file` with `read ... <&3`, and
`</dev/null` on every ssh in a loop that reads a list.
