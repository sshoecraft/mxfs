---
name: sess380-scst-atomic-wait-cycle-ROOT-CAUSE-AND-FIX
description: sess380 ROOT CAUSE: the 60s quantum behind #526B and #379 was a wait-for CYCLE in SCST's CAW-overlap blocker graph, NOT MXFS. Fixed in scst .3; 120.5…
metadata:
  type: project
tags: [sess380, scst, target, deadlock, 526B, 379, infra, root-cause, fixed]
---

# sess380 — the 60-second quantum was a deadlock in the SCST target, not MXFS

## What it is

`scst_check_scsi_atomicity()` (scst/src/scst_targ.c) walked the WHOLE
`dev_exec_cmd_list` and skipped only the command itself (`continue`, not
`break`), so a command whose FIRST atomicity check is DEFERRED installs wait
edges back to commands that are already blocked ON IT. Mutual wait. Nothing
but the initiator's ABORT_TASK breaks it.

The deferral is reachable and routine:

1. `scst_do_check_blocked_dev()` appends the cmd to `dev_exec_cmd_list`
   BEFORE the atomicity check.
2. The check is skipped entirely when the cmd is not SCSI-atomic AND
   `dev->dev_scsi_atomic_cmd_active == 0` — so `scsi_atomicity_checked`
   stays 0.
3. The cmd is then parked by a DEVICE block (`block_count > 0`) and **stays
   on `dev_exec_cmd_list`**, collecting every overlapping CAW as a waiter.
4. Device unblocks; the cmd re-enters; `dev_scsi_atomic_cmd_active` is now
   nonzero (its own waiters) and `scsi_atomicity_checked` is still 0, so it
   runs its first check NOW and blocks on its own waiters.

## The trace that proves it (TRACE_BLOCK, one LBA, 32 initiators)

```
536846.409771  Device BLOCK (new count 1)
536846.409778  Delaying cmd 48a9c59d due to blocking (tag 119, op READ(16))
536846.409819  Delaying CAW 1d61a266 (blockers 1) due to overlap with 48a9c59d
536846.409849  Delaying CAW ff98f7ea (blockers 1,2) ... incl. 48a9c59d
   ... 4 more CAWs block on 48a9c59d ...
536846.419048  Device UNBLOCK (new 0)
536846.419053  Adding blocked cmd 48a9c59d to active cmd list
536846.419087  Delaying cmd 48a9c59d (READ(16), blockers 1..5) due to overlap
               with 1d61a266, ff98f7ea, 0efda8f0, fca86073, 04c78c3a  <-- its own waiters
   ... 60 s of nothing ...
536906.823647  Aborting cmd 48a9c59d ... state EXEC_CHECK_BLOCKING, proc time 60 sec
536906.823672  Unblock aborted atomic-blocked cmd 48a9c59d
```

Supporting aggregates over a 95 s window: block/unblock accounting is EXACT
(216 blocked = 204 normal unblocks + 12 abort-released; 90 dev BLOCK / 90
UNBLOCK; 340 dev-block parks / 340 reactivations) — so it is NOT a leak, and
the wait distribution is strictly BIMODAL (p50 8 ms, p90 53 ms, then 4 samples
0.1-1 s, 1 in 1-10 s, 6 over 10 s, max 60.414 s). A queue with an 8 ms median
does not produce a 60 s tail from 336 commands.

Why reads alone never trigger it (the sess379 negative control): with no CAW,
`dev_scsi_atomic_cmd_active` stays 0, so no atomicity check ever runs.

## The fix — scst 3.11.0-pre+caw-abort-reclaim.3

`continue` -> `break` at self in `scst_check_scsi_atomicity()`: install edges
only toward PREDECESSORS. `dev_exec_cmd_list` is append-at-tail only with
exactly ONE insertion site (scst_targ.c:362, guarded by `!on_dev_exec_list`)
and ONE removal site (scst_targ.c:504, in `__scst_check_unblock_dev`, which
releases every edge pointing at the cmd first) — audited, so list position is
a stable admission order and the wait-for graph is acyclic by construction.

Nothing is lost: for every overlapping pair with at least one SCSI-atomic
member, one direction of the edge is still installed (later waits for earlier),
which is what SBC requires — it does not dictate which of two overlapping
commands wins.

Also landed: a `dev_exec_seq` stamp on `scst_cmd` + `dev_exec_seq_next` on
`scst_device`, and a `WARN_ONCE` if an edge is ever installed non-backward —
the standing detector for the invariant the DAG proof rests on. And
`out_busy_undo` now mirrors the forward walk (stops at chk_cmd) and guards
`count > 0`, which the new walk requires.

RULE-5 reviewed before landing (GPT approved the shape, required the
list-stability audit, and asked for the orientation detector).

## Measured A/B — nothing changed in MXFS between the two columns

MXFS 0.15.4 sv DACACDDE464B211CF68DE3F on both.

| measurement (28 of 32 simultaneous umount) | scst .2 | scst .3 |
|---|---|---|
| max umount wall | **120.48 s** (8/32 over budget) | **0.37 s** (0/28) |
| worst read on hot slot LBA | 60,426 ms | 59 ms |
| worst CAW on hot slot LBA | 60,415 ms | 53 ms |
| summed service time, that sector, fleet | 719 s | 2.1 s |
| ABORT_TASK / abort-reclaims | 12 / 12 | 0 / 0 |

32 of 32 simultaneous: max **0.25 s**, mean 0.12 s (sess379: 31/32 stalled,
max 60.65 s).

Paired direct READ(16)+FUA, hot vs cold LBA on the same nexus during the
storm (`tests/lba_probe.sh`, the form the sess379 RULE-5 review prescribed):
hot n=4084 worst 68 ms mean 4 ms | cold n=4084 worst 24 ms mean 4 ms.
sess379 on the broken target: 40,272 ms vs 39 ms.

Observer stat probe, the ACCEPTANCE form (32 nodes converging on one shared
resource): worst `stat` of the contended mount root **13 ms** vs worst `stat`
of an uncontended file **8 ms** over 1417 pairs = **1.6x**, inside the
defect's stated 2x bar. sess379: 59,742 ms vs 3 ms.

## Deploy recipe (worked verbatim, ~10 min)

Same as sess140 plus one step: the fence stack holds 2 sessions, so run
`tests/fence_inflight/stack.sh down` before the rmmod.

1. 32 nodes: `umount /mnt/shared; rmmod mxfs; multipath -f mpatha;
   iscsiadm -m node -u; iscsiadm -m node -o delete`
2. `tests/fence_inflight/stack.sh down`
3. `scripts/scst_setup.sh teardown`
4. `pkill iscsi-scstd` FIRST, then `rmmod iscsi_scst scst_vdisk scst`
5. `cd /src/scst/scst && make && sudo make install`;
   `cd /src/scst/iscsi-scst && make && sudo make install`; `depmod -a`
6. `scripts/scst_setup.sh setup`; `scripts/rig.sh mpath 32`;
   `./run.sh 32 caw prep_cluster`

`scst.ko`'s srcversion does NOT move for header-only changes — check
`cat /sys/kernel/scst_tgt/version` instead.

## Standing gotchas

- The node device is `/dev/mapper/mpatha`, NOT `/dev/sda` (sda is one path and
  is claimed by multipath, so `mount /dev/sda` fails with EBUSY). Raw `sg_raw`
  passthrough still uses `/dev/sda`.
- clyde's kernel ring holds only ~10 s of SCST block tracing under a 32-node
  storm. Stream it: `sudo dmesg -w > file &` for the whole run, don't
  post-hoc `dmesg`.
- Enable with `echo "add block" > /sys/kernel/scst_tgt/trace_level`, and
  `del pr` or the PR dumps drown everything.
