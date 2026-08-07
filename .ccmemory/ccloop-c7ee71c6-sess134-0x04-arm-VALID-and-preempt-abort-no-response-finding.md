---
name: ccloop-c7ee71c6-sess134-0x04-arm-VALID-and-preempt-abort-no-response-finding
description: sess134: 0x04 arm now scores VALID (violation +12.383s). 0x05 arm proved P&A WAITS (PROUT blocked 12.382s) but drops the victim's cmd with NO respons…
metadata:
  type: reference
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, fencing, scst, test-harness, iscsi]
---

# sess134 — 0x04 arm VALID; 0x05 exposed a real target/initiator behavior

## 1. Scorer bugs fixed in `tests/fence_inflight/verdict.py`
Three, not two.  The sess133 0x04 run was a good experiment scored by a broken
scorer; it now scores **VALID** and so does a fresh re-run.

1. **`EH_MARKERS` contained `"reservation conflict"`** — property (C) provokes
   exactly one on purpose.  Removed from the blanket list and replaced with a
   STRICTER pair:
   - `4b_conflicts_all_accounted`: count of sd-layer
     `sd H:C:T:L: reservation conflict` lines MUST equal the number of probe
     commands that themselves reported RESERVATION_CONFLICT.  Catches both an
     unexpected conflict and an unexplained one.
   - `4c_held_write_admitted`: the held write must not have been conflict-
     rejected (the "never admitted" wrong answer).
2. **`6_target_observed_sa` grepped dmesg** — replaced with ftrace, which is
   direct and immune to the SCST trace level.  Justified from source
   (`/src/scst/scst/src/scst_pres.c`): `scst_pr_preempt()` calls
   `scst_pr_do_preempt(abort=false)` and NEVER `scst_pr_abort_reg()`;
   `scst_pr_preempt_and_abort()` calls `scst_pr_do_preempt(abort=true)` which
   calls `scst_pr_abort_reg()` per preempted registrant.  So
   0x04 => do_preempt yes / preempt_and_abort no / abort_reg no;
   0x05 => all three present.
3. **`7_common_timeline` required `t_land`** — would have failed the 0x05 arm
   spuriously if the write never reached the medium (a BETTER outcome, not a
   broken measurement).  Now: boundary exists AND `trace_clock` really was
   `[mono]`.  `inflight_ab.sh` now RECORDS `trace_clock.txt` and aborts the arm
   if it is not mono; verdict.py refuses to score without that file.
   (Consequence: the sess133 artifact `/var/tmp/fence_ab.slM1Ly` scores INVALID
   on item 7 only because it predates the capture — it is a preliminary.)

Also: **0x05 boundary must be `last()` not `first()` of
`scst_cmd_done_pr_preempt`.**  That hook fires once per pending PR_ABORT_ALL
mgmt cmd plus once for the PROUT's own exec-done; only the call that drives
`pr_abort_pending_cnt` to 0 restores `saved_cmd_done` and actually completes the
PROUT.  `first()` can precede the real completion and would fail the safety arm
spuriously.  `last()` is still strictly earlier than the wire GOOD.

## 2. RESULT — 0x04 arm re-run, VALID (`/var/tmp/fence_ab.vKHE6R`)
```
write bio queued at dm-delay      +0.000155
PROUT 0x04 submit                 +0.022815
scst_pr_do_preempt                +0.022990
PROUT return (GOOD, 0.232 ms)     +0.023112
LOWER-DEVICE WRITE COMPLETE      +12.405836
```
margin = **+12.382724 s** (land - boundary).  (A) FAIL, (B) FAIL,
**VIOLATION SHOWN: YES**, (C) PASS.  All 12 validity items ok
(10_replay_gate n/a until the C3 stage).  Final O_DIRECT read below dm-delay:
`first=0xa4` (victim pattern) at the observation offset, `0x11` (clean) at the
property-C offset.  ftrace: do_preempt=True, preempt_and_abort=False,
abort_reg=False — target-side proof the SA really was plain PREEMPT.
Reservation conflicts: 1 in dmesg, 1 reported by probes.

## 3. 0x05 arm — P&A DOES wait, and a NEW finding
`PROUT 0x05 blocked for 12381.904 ms` and returned GOOD only after the victim's
held write completed at the device.  That is the linearization property 0x04
lacks — the discriminator is real.  (Arm not yet scored; see §4.)

**But the arm hung.**  dmesg, verbatim:
```
iscsi_xmit_response:3385:req ... (scst_cmd ...) aborted
req_cmnd_release_force:575:req ...
cmnd_done:411:Done aborted cmd ... state 5
scst_free_cmd:7847:Freeing aborted cmd ...
```
With TAS off, SAM REQUIRES the aborted command be dropped "without delivery or
notification" (`scst_lib.c::scst_xmit_process_aborted_cmd`), and SCST does
exactly that — **no PDU is sent to the victim**.  libiscsi's `eh_cmd_timed_out`
then keeps returning BLK_EH_RESET_TIMER while the connection is healthy, so the
initiator NEVER times the command out.  Measured: the SG_IO caller was still in
`D` state in `blk_execute_rq` **261 s after** its 120 s SG_IO timeout.  The
vdisk has no `tas` sysfs attribute, so TAS cannot simply be flipped on.

**This is a design consequence for MXFS, not just a harness nuisance:** switching
the fence from 0x04 to 0x05 means a fenced node's in-flight I/O never completes
AND never errors — it hangs rather than getting EIO.  Whatever ships must not
assume the victim learns anything.

**Recovery:** only session teardown fails such a command.  Added
`stack.sh relogin <victim|survivor>`.  Trap: the logout drops the iface binding
on the node record, so a plain `--login -I <iface>` afterwards says
"No records found" — `relogin` now recreates the node record (`-o new` +
replacement_timeout) before logging in, and polls up to 30 s for the disk.
Verified working: victim came back as /dev/sda.

## 4. NEXT — restructure `inflight_ab.sh`, then finish the ruled order
The arm currently does `wait $WPID` on the held write BEFORE gathering evidence.
For 0x05 that blocks forever.  Nothing the arm concludes needs the held write to
return at the initiator — `t_land` comes from ftrace on the loop device and the
bytes come from an O_DIRECT dread below dm-delay.  So:
1. After PROUT returns, go straight to property (C), the drain, `tracing_on=0`,
   post-state PRINs, final dreads, dmesg capture — the whole measurement window
   (~31 s, comfortably inside the ~120 s+ before any initiator EH could fire).
2. ONLY THEN reap WPID; if still running, `stack.sh relogin victim` to release
   it, record `held_write_answered=0` in arm.env, and capture a SECOND
   `dmesg_post.txt` so the post-window EH is recorded, not hidden.
3. verdict.py: `4c` must pass when `write_done` is absent entirely (item 3
   already proves admission via the target's `active_commands` + the dm bio);
   `4b` probes list tolerates an empty `w_done`.
Then run the ruled order 0x04 -> 0x05 -> 0x04.  0x04 is already banked twice.

Rig left CLEAN: tracing_on=0, tracer=nop, dm-delay 0, both fence sessions up
(victim=/dev/sda survivor=/dev/sdb), production target still at 64 sessions,
no stray prprobe.  Teardown when done: `sudo bash stack.sh down`.
