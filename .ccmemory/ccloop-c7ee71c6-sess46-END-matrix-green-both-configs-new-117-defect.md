---
name: ccloop-c7ee71c6-sess46-END-matrix-green-both-configs-new-117-defect
description: sess46 END (0.11.373 deployed): routed open-unlink DONE (matrix 9/9 both configs); NEW critical D-REAP-IFREE-117 (1 hit, 3 no-repro, probes complete)…
metadata:
  type: project
tags: [ccloop, session-end, sess46]
---

# sess46 END — state for the relay (final, supersedes earlier same-name)

## RIG: 32/caw SHIP CONFIG (knob=0, tracking=1) on 0.11.373
(691714A3B35E853F0E417FB), fresh prep, sanity green (cc 654/654, zsl
644/644, dirent_durability 30r/0loss). Marker current.

## SCORECARD
1. D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY: ICLUSTER open-tracking port
   COMPLETE and verified — matrix 9/9 at knob=1 (368/369/372) AND knob=0
   (372 fresh prep ×2 + aged ×2). Refusal lifted. FIVE knob=1 roots fixed
   en route + retention fixes on shipped per-inode paths (repair was
   wiping open_holders). Remaining for closure: knob=1 clean-load board
   (drc/crash zero-margin rows), GPT items 2-4, slot telemetry,
   default-ON + PROTO_GEN bump. Details:
   ...-routed-opentrack-matrix-9of9, ...-knob1-pace-recalibration.
2. NEW CRITICAL D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372 (OPEN): ship
   config, FRESH fs, xfs_ifree -117 → 0x1 shutdown → withdrawal (test2,
   ino 67108994) during a matrix that followed the rsync lap on an aged
   prep. THREE targeted repro attempts clean (fresh matrix; aged
   lap→matrix; crash-killed→matrix). 0.11.373 completes P-DIFREE-CORRUPT
   coverage (every -EFSCORRUPTED exit under xfs_difree self-names).
   test2's ring was LOST to re-prep before full capture — STANDING RULE:
   dmesg > /root/<tag>.dmesg on a shutdown node BEFORE any recovery.
3. rsync laps: 8 clean (6A+2B), P217=0 fleet-wide throughout.
4. crash_consistency: NO clean-window knob=0 PASS achieved today (bursts
   to load 88 all day; clean_load_run.sh got 10 contaminated attempts).
   NOTERMINAL-354 unchanged; the census machinery works (phase
   distributions captured 3×: barrier-ready/datawrite/md5write splits).

## LEDGER: 12 OPEN of 39. Criticals: FOREIGN-REPLAY, INODE-CLUSTER-PUBLISH
(campaign active), CROSSNODE-OPEN-UNLINK (TCP arm only now — CAW both
routing modes verified), RSYNC-RENAME (containment armed, lapping),
REAP-IFREE-117 (probes armed).

## RELAY QUEUE
1. REAP-IFREE-117: keep matrix-after-varied-aging in the lap rotation;
   probes will self-name the exit on recurrence.
2. rsync laps per task #1 (alternate arms; load-gate <18).
3. knob=1: clean-load full board → GPT items 2-4 → default-ON decision.
4. crash_consistency clean-window PASS at knob=0/373 (use
   tests/clean_load_run.sh GATE=16 CLEAN=25 in a quiet stretch —
   overnight windows are cleaner).
5. Then: FOREIGN-REPLAY (certified replay, sess17 design), TCP rig wiring
   (host LUN + VM XML) for CROSSNODE-OPEN-UNLINK's TCP arm + MATRIX-
   UNMEASURED.

## DO-NOT-RE-DERIVE (top items; full list in the pace memory)
- drc: 58 checks = 8 rounds = zero margin; judge only hostload<22 runs.
- Bit-carrying tombstones cannot exist; B6 probe stays find_slot-cheap.
- Publication ownership = config predicate; opens must be cluster-backed.
- covered_active/fan_out stay sticky-keyed; selfclear skips acquiring ino.
- prep mkfs's every forced prep; idle LUN ≈30 iops/node baseline.
