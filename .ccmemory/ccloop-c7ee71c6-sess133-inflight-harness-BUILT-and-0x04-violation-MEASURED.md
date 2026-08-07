---
name: ccloop-c7ee71c6-sess133-inflight-harness-BUILT-and-0x04-violation-MEASURED
description: sess133: step-4 harness BUILT and working; 0x04 arm MEASURED the defect (12.089s post-return landing). Disposition RULED: (B) linearization is the c…
metadata:
  type: reference
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, fencing, rule5-ruling, test-harness, scst]
---

# sess133 — the in-flight exclusion harness exists, and 0x04 reproduced the defect

## 1. Disposition RULED (gpt-5.6-sol) — the sess132 open question is answered
**"FIXED AND VERIFIED is justified after the ledger criterion is formally
corrected from cancellation to linearization, the response boundary is measured
at actual SCSI PR completion, and the real MXFS replay gate is established."**

Replacement criterion, verbatim: *"Once PREEMPT AND ABORT has successfully
completed, no command belonging to a preempted victim nexus may subsequently
modify the protected medium."*  Property (A) cancellation is NOT what SCSI P&A
promises (terminate/drain, not undo).  The ledger entry has been formally
AMENDED (not silently reread) — the old "bytes NOT on the platter" text is
recorded there as technically invalid and withdrawn.

Three NEW mandatory closure requirements, all now in the ledger `next`:
- **C1** boundary measured at real PR completion, common monotonic timeline.
- **C2** property **(C) CONTINUED EXCLUSION** — post-fence victim write must get
  RESERVATION CONFLICT and not modify the store.
- **C3** prove the SURVIVOR does not start replay early.  Expected to FAIL on
  the shipped build (sess92: `mxfs_disklock_recovery_fence_certify()` has ZERO
  callers) — that is D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION.
Plus a 10-item validity predicate and an invalidate-don't-reinterpret list.

## 2. The conservative-boundary trick (solves C1 cheaply)
`trace_clock=mono` makes ftrace timestamps ARE CLOCK_MONOTONIC, directly
comparable with userspace `clock_gettime`.  Then pick the boundary PER ARM so
each direction is conservative — no need to function-trace the whole iSCSI
response path:
- **0x05 safety arm**: boundary = ftrace entry of `scst_cmd_done_pr_preempt`,
  which is strictly EARLIER than the wire GOOD -> "landed before" is STRICTER.
- **0x04 violation arm**: boundary = userspace PROUT return, strictly LATER than
  the wire GOOD -> "landed after" is a STRICTER demonstration.
All four SCST symbols are traceable on clyde: `scst_pr_do_preempt`,
`scst_pr_abort_reg`, `scst_pr_preempt_and_abort`, `scst_cmd_done_pr_preempt`.

## 3. What was built (all in `tests/fence_inflight/`, RULE 3)
- `prprobe.c` — SG_IO probe.  sg_persist 0.67 has NO timeout option and sysfs
  device timeout does NOT govern SG_IO.  Subcommands: `prout` (full PROUT with
  controlled `sg_io_hdr.timeout`), `prin` (READ KEYS / RESERVATION / CAPABILITIES
  / FULL STATUS with TransportID decode), `write` (WRITE(16)), `poll` (aligned
  O_DIRECT observation below dm-delay), `dwrite`, `dread`, `clearua`.
  Reports scsi/host/driver status, sense, resid, errno, duration, mono stamps.
- `stack.sh` — isolated stack: preallocated+initialized image -> loop
  (`--direct-io=on`, VERIFIED `/sys/block/loopN/loop/dio`=1) -> dm-delay
  (switchable write delay via suspend/reload/resume) -> SCST vdisk_blockio
  `fencedelay` -> `iqn.2026-08.mxfs.fence:inflight` -> TWO local iSCSI sessions
  on ifaces `fnc_v`/`fnc_s` with distinct `iface.initiatorname`.
  Production `iqn.2026-05.local.mxfs:shared` stays at 64 sessions, untouched.
- `inflight_ab.sh` — one arm end to end.  `verdict.py` — scores it.

## 4. Facts established on the rig
- **Two distinct I_T nexuses CONFIRMED AT THE TARGET** (not assumed): SCST
  sessions dir lists both IQNs, and READ FULL STATUS shows distinct
  TransportIDs with distinct ISIDs (`...,i,0x100003d0200` vs `0x200003d0200`).
- Target REPORT CAPABILITIES: `ptpl_c=1 type_mask=0xea01` -> WE-RO (type 5) offered.
- MXFS production shape mirrored: REGISTER(0x06) then RESERVE
  `PR_WRITE_EXCLUSIVE_REG_ONLY` (dlm/mount.c:1971/1980, v5_mount.c:3405/3427).
  Harness = victim registrant + survivor registrant holding WE-RO.
- **Delay stack validated standalone: 12097 ms for W=12000 ms.**

## 5. TWO TRAPS that cost a run each — do not rediscover
- **PROUT CLEAR posts a Unit Attention to the OTHER nexus**, so the victim's
  next REGISTER returns CHECK CONDITION and silently fails, leaving it
  unregistered -> its write gets RESERVATION CONFLICT before execution (exactly
  the "write never admitted" wrong-answer risk).  FIX: `prprobe clearua` (TEST
  UNIT READY loop) on BOTH paths after CLEAR, plus assert `good=1` on every
  setup step and assert both keys present before the trial.
- **`/sys/block/dm-N/inflight` NEVER rises for deferred bio-based dm IO** — it
  is the wrong in-flight probe.  The right one is SCST's own
  `targets/iscsi/<tgt>/sessions/<initiator_iqn>/active_commands` = the victim's
  TASK-SET SIZE read from the target.  That is literally the property the ruling
  demands, not a device-layer proxy.

## 6. RESULT — 0x04 arm, the defect MEASURED (`/var/tmp/fence_ab.slM1Ly`)
Relative to the victim write submit:
```
write bio queued at dm-delay      +0.000239
PROUT 0x04 submit                 +0.024591
scst_pr_do_preempt                +0.024842   (target parsed it)
PROUT return (GOOD, 0.311 ms)     +0.024972
LOWER-DEVICE WRITE COMPLETE      +12.114131   <-- 12.089 s AFTER the fence returned
poller first sees the pattern    +12.150998
```
- margin = **+12.089159 s (land - boundary)** — the forbidden post-return landing.
- Final O_DIRECT read below dm-delay: `first=0xa4` = the victim's pattern on the
  backing store.  **(A) FAIL, (B) FAIL, VIOLATION SHOWN: YES.**
- `scst_pr_preempt_and_abort` and `scst_cmd_done_pr_preempt` did NOT fire —
  target-side proof the service action really was plain PREEMPT.
- **(C) PASS**: post-fence victim write -> `scsi_status=0x18
  RESERVATION_CONFLICT=1`, second offset still `0x11` (clean).
- Post-state: victim key gone, `prin_keys count=1` survivor only, WE-RO held.

## 7. NEXT — two `verdict.py` scoring bugs (experiment was fine, scorer wasn't)
The run above is scored INVALID by two scorer artifacts.  Fix these FIRST:
1. `EH_MARKERS` contains `"reservation conflict"`, but property (C)
   DELIBERATELY provokes one.  Remove it, or exclude the expected post-fence one.
2. `6_target_observed_sa` matches dmesg strings.  Replace with the FTRACE
   evidence, which is stronger and already captured: 0x04 => `scst_pr_do_preempt`
   present AND `scst_pr_preempt_and_abort` ABSENT; 0x05 => both present.
Then: run the 0x05 arm, then 0x04 again (ruled order 0x04 -> 0x05 -> 0x04 so the
discriminator is shown not to have evaporated).  Then stage (ii) on
vdisk_fileio, then stage (iii) real-MXFS on-wire, then (C3) the replay gate.
Teardown when done: `sudo bash tests/fence_inflight/stack.sh down`.
SCST `pr` tracing is still ON (`del pr` to disable); measured 0 lines/20s idle.
