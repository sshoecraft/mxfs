---
name: ccloop-c7ee71c6-sess24-wedged-node-fakes-broken-fs-and-mqtt-backlog
description: Two board-lie root causes: one sync-wedged node makes 7 criteria read 0/32, and 120k retained MQTT messages crawl every barrier. Both now gated in ru…
metadata:
  type: project
tags: [board-lie, harness, mqtt, coord, false-red, run.sh, precond]
---

# Two infrastructure faults that both present as "the filesystem is broken"

sess24. Both cost most of a session. Both now gated in run.sh.

## 1. ONE sync-wedged node -> `nodes_pass=0/32` on SEVEN criteria

A node deadlocked by D-BAST-WRITEBACK-ABBA-DEADLOCK passes every liveness
check: mxfs mounted, `ls` answers, mkdir/write/fsync/unlink all fine, no
BUG/WARNING, no shutdown. It simply can never finish `sync`, so it never
reaches a barrier.

Barrier criteria need every rank. Result: cache_coherency,
strong_consistency, posix_multi, mmap_coherency, zero_silent_loss,
dlm_fairness and dlm_membership ALL reported

    FAIL nodes_pass=0/32 states:NO_TERMINAL_RECORD=32

with 31 of 32 nodes healthy. After `virsh destroy+start test27` +
re-prep, all seven PASS at original timings (cache_coherency 25s,
strong_consistency 4s). crash_consistency also went FAIL 90/90s ->
PASS 64s/90s.

### How to identify the straggler
Run the criterion OUTSIDE run.sh with a generous timeout. Under run.sh
the outer `timeout $tt` kills the node script before coord_barrier's own
COORD_TIMEOUT fires, so node files hold only blank preamble and nothing
says who was late. With headroom, 31 of 32 nodes reported and named it:
`sc node27 last counter(exp=node27_seq20 got=node27_seq1)` on 16 nodes,
`sc barrier write-done` on 15.

### Discriminator: is the FS actually slower?
`dir_reuse_coherency` is not gated on a single node's writeback. It was
unaffected throughout (10 rounds / 110s). If DRC is normal while barrier
criteria collapse, suspect a wedged node, not the filesystem.

### The gate (run.sh per-test pre-assert)
Separate sync-liveness pass; a node that cannot `sync` in bounded time is
recorded **BLOCKED**, naming node + D-state stacks, never a correctness FAIL.

Two traps, do not repeat:
- **Predicate must be the bounded `sync`, NOT a D-state scan.** Convicting
  on any D-state mxfs task FALSE-BLOCKED healthy test26 for
  `mxfs-worker[mxfs_pal_cond_timedwait]` - that is the normal bounded CAW
  acquire poll. D-state is attribution for an already-convicted node.
- **Must be its own ssh pass.** A wedged `sync` is UNINTERRUPTIBLE, so
  `timeout 12 sync` never returns, the outer ssh is killed, and the node
  lands in the mount bucket reading "mxfs not mounted/readable". For this
  probe, silence IS the positive result.

## 2. 120,447 retained MQTT messages under mxfs/coord

run.sh cleared only its OWN `mxfs/coord/<RUN_ID>/<test>` prefix, so every
prior run's retained state accumulated forever. coord_barrier subscribes
by wildcard, so a backlog that size makes every barrier crawl.

Now `coord_broker_hygiene()` sweeps the WHOLE `mxfs/coord/#` namespace at
startup (the flock serialises runs, so nothing live is destroyed), and
**aborts the run** if it cannot reach a clean state - infrastructure
degradation must never present as a filesystem verdict.

**`mosquitto_sub -W` is an ABSOLUTE exit timer, not an idle window.** A
bare `-W 300` sweep added 300s to EVERY run. The sweep now probes first
and only sweeps when there is something to remove.

## 3. Where run.sh actually keeps node logs

The `logs: /tmp/tmp.XXXX` line names a directory that run.sh then
`cp -r`s to `/tmp/run_<name>_<RUN_ID>` and **deletes**. Reading the
printed path shows an empty dir and looks like "no node produced output".
Read `/tmp/run_<name>_<RUN_ID>` instead.

## 4. dmesg ring retention varies ~60x across one cluster

test19 held 1964 lines / 109s; test25 held 136966 lines / 1107s. Any
criterion that scopes on a kmsg marker older than ~2 minutes will lose it
on short-ring nodes. dirent_durability now also records the window start
as a kernel-monotonic timestamp in a file; `lib.sh::dirent_window_scope`
falls back to scoping BY TIMESTAMP and reports win_src / win_trunc.

**Trap:** calling that helper as `$(dirent_window_scope)` runs it in a
SUBSHELL, so its globals are lost, `have_window` is EMPTY, `[ "$x" = 0 ]`
is false, and the scanners report PASS with every count zero - a vacuous
green, worse than the false red. It writes to a file and fails closed now.
