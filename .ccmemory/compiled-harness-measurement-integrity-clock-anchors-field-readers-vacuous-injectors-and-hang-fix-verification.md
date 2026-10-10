---
name: compiled-harness-measurement-integrity-clock-anchors-field-readers-vacuous-injectors-and-hang-fix-verification
description: Harness techniques: anchor cross-node boottime via /proc/uptime, multi-field readers, loud vacuous injectors, time the hung op, rotor attribution.
metadata:
  type: feedback
tags: [compiled, harness, measurement-integrity, technique, fault-injection, verification]
---

Five harness and measurement-integrity techniques share one theme: a number or a verdict is only as good as the check that the instrument measured what it claims. Each one is a way a lap produced a graded result that meant nothing, or a way to catch that before it did.

## Cross-node timestamps (clock anchoring)

[[technique-reconcile-two-nodes-module-timestamps-through-proc-uptime-and-check-the-anchor-against-the-same-lines-dmesg-prefix]]

- Every `*_ms` field the module prints (`deadline_ms`, `now_ms`, `anchor_ms`, `issued_ms`, `last_ok_ms`) is `mxfs_pal_time_ms()` = `ktime_get_boottime_ns()/1e6` (`pal/linux/kern.c:2970`). It is boot-relative, so two nodes' values are on unrelated origins. Subtracting one node's value from another's yields a number that looks like seconds and means nothing.
- Anchor each node in ONE remote command: `printf 'ANCHOR up=%s wall=%s\n' "$(cut -d' ' -f1 /proc/uptime)" "$(date +%s.%N)"`. `wall_at_boot = wall - up`; any boottime-ms value becomes wall seconds as `wall_at_boot + ms/1000`. `/proc/uptime` is the same clock as boottime. NTP skew of a few ms is irrelevant against windows of seconds.
- Check the anchor, never trust it. A kernel line carrying `now_ms` also carries a dmesg prefix (`[ 5169.041]`). Convert both through the same anchor; they must land on the same wall instant. If they differ by more than a few seconds, ABORT. The node suspended, the clock stepped, or dmesg's `local_clock` differs from boottime. Reporting a margin anyway reports arithmetic, not a measurement.
- Implemented in `tests/authority_handoff_phase.sh` (`anchor_of`, `wall_of`, `dmesg_wall`, `ANCHOR_TOL_S` gate).

## Harness field readers

[[trap-a-line-anchored-field-reader-silently-empties-every-field-after-the-first-on-a-multi-field-line]]

- Sixteen fence harnesses carried `field(){ grep -ao "^$2=[^ ]*" ... }`. The `measure` convention prints several fields per line (`SEEN=1 PAUSED=1`); the `^` anchor makes only the first readable and every later field comes back empty.
- `ck` correctly refuses to grade an empty value and aborts the lap, so a healthy lap aborted at an assertion about a subsystem that worked (`PAUSED=1` was sitting in the capture file). The reader lied, not `ck`.
- Fix (0.89.20, all sixteen): `grep -aoE "(^| )$2=[^ ]*"`. When adding a field to an existing arm's print, verify the reader can see it; nothing warns.

## Fault injectors that can be armed into a no-op

[[technique-a-fault-injector-that-can-be-armed-into-a-no-op-must-decline-loudly-and-before-the-destructive-step]]

- Case: the partial-replay cut (submit N of the queued buffers, withhold the rest). If N >= queued there is no suffix and the experiment silently becomes its own control.
- The module counts the queue, refuses a cut that leaves no suffix or no prefix, prints `P-DBG-REPLAY-CUT-VACUOUS` with both numbers, then submits normally so the filesystem stays consistent. The harness checks for that line between capturing the prover's window and destroying the prover VM.
- First lap: `want=8 queued=1`, cost 137 s; without the guard, two VM boots, ~20 min and a verdict on a cut that never happened.
- Three properties: the injector decides vacuity (only it sees the runtime quantity; a harness prediction is a guess); it declines loudly and proceeds safely (silent no-op or silent best-effort both produce a graded lap); the check precedes the irreversible step.
- Generalises to any injector whose effect depends on a runtime quantity: torn record at byte K, kill after N of M, a delay shorter than what it delays.

## Verifying a hang fix

[[technique-verify-a-hang-fix-by-timing-the-operation-that-hung-not-by-the-absence-of-the-hang]]

- A lap that completes without hanging is weak evidence; it may never have attempted the blocking operation. Run the exact operation that hung, bounded by a derived `timeout`, and record wall time and rc on both builds.
- D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381: `stat` through the mount retried 764 693 ms and climbing before, EIO in 4 s after. `umount`+`rmmod` hung before (module unreleasable, only `virsh destroy` cleared it), after `UMOUNT_RC=0 MOUNTED_AFTER=0 RMMOD_RC=0 MODULE_PRESENT=0` in 3 s.
- A probe counter 0 before and 1 after (`P240-RBLK-EIO-ABORT`) names the mechanism that changed and outweighs any wall-clock number.
- Fold the check into the harness, bounded, so the fix cannot regress unnoticed. An unbounded `umount` on a wedged filesystem makes the check the next wedge.

## Attributing an inode to a lap round after the volume is gone

[[technique-a-single-node-directory-rotor-anchors-which-lap-round-created-an-ags-first-inode]]

- D-0957: a cold `chk_mxfs` found AG 4 agino 128 (ino 33554560) inobt-allocated with a chunk-init core (mode 0, changecount 0); the volume had been re-mkfs'd many times and dmesg had rotated.
- agino 128 is the first inode of an AG's first aligned chunk on this geometry (512-byte inodes, 8-block alignment, first chunk at agblock 16). In `xfs_ialloc.c` the directory AG is pinned to the node slot under multi-node membership and steps `(node_slot + m_agirotor++) % maxagi` only when single-node. During a sole-survivor phase every mkdir advances the AG by one, including a harness `mkdir -p probe && rmdir probe`. The rotor is per mount and survives across laps while mounted.
- Two logged anchors (P-CR3-CANCEL parents: round 1 = AG 11, round 3 = AG 13) plus counting mkdirs backwards placed the earlier lap's round 3 in AG 4, a knob=1 round of the partial-write-filter-without-grants arm.
- Rules: count every mkdir including probes and rmdir'd scratch dirs; the walk is valid only across the single-node span; record the assumption (one mkdir per round, one probe mkdir per sole phase) next to the conclusion since it is inference, not a platter read; a knob toggled per round whose later flush lands an earlier dropped image strands fewer objects than there are knob=1 rounds, so one stranded directory out of three is the expected shape.
