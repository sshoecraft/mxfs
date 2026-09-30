---
name: trap-a-harness-that-waits-out-a-fixed-window-unmounts-under-the-loads-last-cycle-and-every-umount-answers-busy
description: TRAP (0.90.30): sf_base_overlap slept LOAD_S+10 then unmounted; the load's last cycle still ran: 7 umounts rc=32 in 0 s, chk never ran.
metadata:
  type: feedback
tags: [harness, umount, load-loop, rig]
---

## What happened

`tests/sf_base_overlap.sh 8 tcp 20000 ctl` started a load loop bounded by
`while [ $SECONDS -lt $end ]`, slept `LOAD_S + 10` on the host, read the
nodes and unmounted. The loop tests its bound only BETWEEN cycles, and with
a 20 ms test delay inside every merge-base capture one rsync+rm cycle
outlasted the 10 s of slack. Every unmount answered `UMOUNT_RC=32 wall=0s
left=1` (busy), the checker never ran, and the lap's summary printed
`load=` empty for every node. The lap was a control arm whose real result
(two nodes down) stood, but the fix arm would have printed FAIL for the
harness's own reason.

## Why it matters

A window measured on the host says nothing about where the guest's loop is.
Anything that slows a cycle (a test delay, a recovery stall, a loaded host)
moves the loop's end past the window.

**How to apply:**
- Give the loop a stop file as well as a deadline
  (`while [ $SECONDS -lt $end ] && [ ! -e /tmp/x.stop ]`), remove it at start.
- Before reading or unmounting: clear the test delay, touch the stop file,
  and wait for the loop's `.done` file with a bound derived from one cycle.
- Read `LOAD=` only after that wait; an empty `load=` in a summary line means
  the loop had not ended, not that it never ran.
- `tests/multi_victim_containment.sh` is not exposed the same way: its loop
  deadline is LOAD_S + 30 and it waits LOAD_S + 25, but its slack is also only
  a cycle wide.
