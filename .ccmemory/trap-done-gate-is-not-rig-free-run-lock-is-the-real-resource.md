---
name: trap-done-gate-is-not-rig-free-run-lock-is-the-real-resource
description: TRAP (sess480): gating a chain on the previous chain's DONE caused a 4-way collision — a build began relinking mxfs.ko while a board's preps shipped…
metadata:
  type: feedback
tags: [harness, rig, run-lock, chain-gate, build]
---

# A chain's `DONE` does not mean the rig is free

`DONE` means one harness finished writing its log. The rig's real resource is
`/tmp/mxfs_run.lock`. Gating on the former while contending for the latter is a
race, and on 2026-09-03 it fired four ways at once.

## What happened

Four chains were launched separately, each `while ! grep -q "^DONE" "$GATE"`.
When chain 116/`s479k` wrote DONE at 23:17:19Z, **all of them woke inside 30
seconds**, and so did a chain-119 instance left parked by the PREVIOUS session
(label `s479a`) that had been waiting on the same gate for over an hour.

- `s479a` won the lock and started the real board (`timeout 1323 ./run.sh 32 caw`).
- Chain 119 `s480b` and chain 120 `s480c` hit `ERROR: another run.sh holds
  /tmp/mxfs_run.lock` and burned their entire launch to a **one-second FAIL**.
- Chain 121 began `make modules KCFLAGS=...` **in the tree** while that board's
  preps were insmod'ing `/src/mxfs/mxfs.ko` over NFS. The relink was killed with
  seconds to spare — `mxfs.ko` mtime confirmed it had not yet landed. Had it
  completed, the board's srcversion would have split across the fleet mid-run,
  silently corrupting a board being collected as closure evidence for the #1
  critical record.

## Three rules this buys

1. **Wait on the lock, not on a log.** `tests/rig_wait_free.sh` blocks until no
   process holds an fd on `/tmp/mxfs_run.lock` and no `make` is running. It walks
   `/proc/*/fd` symlinks and `comm` — never `pgrep -f` / `ps aux`, which read
   every process's `cmdline`, take its `mmap_lock`, and have wedged this host.
2. **Sequence, don't fan out.** Independent chains racing for one exclusive
   resource is a design error. `tests/sess480_chain122_sequencer.sh` runs the
   stages in one process with a rig-free wait between each.
3. **A build is a rig operation.** `make modules` is exclusive with any run,
   because the preps ship the tree's module. Never launch a build on a gate that
   another rig chain also waits on.

## And a second-order trap it exposed

Editing a chain script while an instance is **parked in its gate loop** corrupts
that instance: bash reads scripts by byte offset, so inserting lines above the
resume point shifts everything. The parked `s479a` resumed into shifted code and
ran its board **detached from its own logging** — the board executed and recorded
to `criteria.json`/`.last_run.json`, but its harness wrote nothing to
`sess479_chain119_board_s479a.log`. Check for parked instances of a script
(`/proc/*/cmdline` for that exact filename) BEFORE editing it, not just for
running ones. The known trap said "never edit a running script"; a script
sleeping in a gate loop counts as running.
