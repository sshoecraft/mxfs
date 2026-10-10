---
name: compiled-teardown-gate-zero-readings-vacuity-controls-and-choke-point-injection
description: A zero on a teardown gate is the staging or an earlier drain, not the gate; positive controls, vacuity as PRECONDITION, injection for unreached arms.
metadata:
  type: feedback
tags: [compiled, measurement-integrity, teardown, authority-gate, vacuity, harness]
---

Shared topic: how to read (and not misread) a zero from a gate that sits on a teardown or never-reached path, and how to make the unreached arm measurable.

## Zero on a teardown gate: find what emptied the producer

- The post-detach metadata arm of the authority gate counted zero twice, and both conclusions drawn ("ordering never reached", then "MXFS skips the one buffer") were about the gate and were wrong. `put_super` runs `xfs_log_quiesce` before sealing and detaching, but only when the SB summary lock was granted. That quiesce empties the AIL, so the post-detach `xfs_ail_push_all_sync` finds nothing. A refused SB lock therefore leaves MORE dirty at detach, the opposite of what the evidence was read to say. Dirtying the filesystem before umount cannot populate this arm because the quiesce drains it. The producer must be created after the quiesce and seal; `dbg_sb_late_dirty` already did that (root inode core logged after the seal), sitting in the tree for ~30 versions under another record's name. See [[trap-a-teardown-gate-reads-zero-because-an-earlier-quiesce-drained-its-producer-not-because-the-gate-is-unreached]].
- Rule: before concluding anything from a zero on a teardown path, list every quiesce, drain and flush between workload and gate and ask which empties the producer. A gate after a drain measures only what was created after it. Then grep the tree for an injection that already produces the population.

## A refused mount's unwind is mute by design

- The mount-failure unwind (`out_unmount`) detaches the DLM before `xfs_unmountfs`, so the window after detach is real, yet lap s92 counted zero `P291-AUTH-META-DETACHED`. The positive control (`P291-AUTH-TAIL-ADMIT`, emitted for any post-detach submission) was also zero: the window never opened. The refused mount had a clean log slice (no recovery) and its quiesce deliberately writes no SB summary (`P960-REFUSED-MOUNT-NOCOVER`, gated on `!mp->m_mxfs_mount_complete`). To make the unwind write, stage a dirty log it must recover. See [[trap-a-refused-mount-unwind-has-nothing-to-write-so-its-zero-is-not-a-measurement-of-the-gate]].
- Rule: a teardown measurement needs a positive control emitted from the SAME window by an already-working path; without one, "zero" and "the window never opened" are the same number. Build the control in from the start and FAIL the lap on a zero control instead of reporting the measurement.

## Making an unreached arm measurable

- For a leak class with one unattributable historical event (D-0924, AG-meta track token), the disposition that holds: (1) prove the lifetime class finite and name its choke points, including grepping for wholesale flag resets and teardown paths that detach the item; (2) return the obligation at every choke point, even the one that looked like a pure diagnostic; (3) write the exclusion argument for the late return next to the code (buffer lock held from submit to completion's relse); (4) exercise the arm a healthy build never reaches with an injection knob (`dbg_agmeta_iodone_skip=N`; epilogue must return exactly N, conservation exact); (5) check conservation per unit (per AG), not only globally; (6) state which routes are measured and which closed by construction. A closure shipped unreached is a claim, not a measurement. See [[technique-close-a-finite-lifetime-class-at-its-choke-points-and-prove-the-unreached-one-by-injection]].
- Evidence trap: injection evidence lands in the first second of churn; at ~700 lines/s the dmesg ring rotated past it before the post-run sweep. Lost-to-rotation is not absent. Stream the ring (`setsid nohup dmesg -w > /dev/shm/x &`) from before the arming marker and grep the stream; confirm the marker survives in whatever is swept.

## Vacuity is a precondition, not a FAIL

- `d0932_retire_pending_takeover.sh` and `d0932_owner_depart_takeover.sh` checked "is the needed state on the platter" with `ckge` (prints `  FAIL`) and then printed `RESULT: VACUOUS` / exit 3. `tests/capture_fault_gate.sh` counts VACUOUS only with exit 3 and zero FAIL lines, so both scored BROKEN on laps the harness itself judged non-measurements (s53b, s59h, s70c). The state is genuinely unreachable in that shape: a clean unmount serialises against the node's parked fence/recovery work, so the departure leaves nothing standing. See [[trap-a-vacuity-precondition-printed-as-a-fail-line-makes-the-capture-gate-score-the-harnesss-own-vacuous-verdict-as-broken]].
- Rule: a check deciding whether the lap can measure anything prints a `STAGE ...` line with the count and takes the VACUOUS exit. Reserve `ck`/`ckge` FAIL lines for assertions about MXFS on a state that was reached. Gate contract: exit 0 = OK; exit 3 with no FAIL lines = VACUOUS (counted apart); exit 1/2 or any FAIL line = BROKEN.
