---
name: trap-a-one-shot-injection-knob-is-not-in-effect-when-the-write-returns-wait-for-the-modules-own-line
description: TRAP (s103): arming dl_inject_hb_pause_ms and measuring immediately lets a beat already in flight satisfy the test; poll for P-HB-INJECT-PAUSE first.
metadata:
  type: feedback
tags: [fault-injection, harness, measurement-integrity, heartbeat]
---

# A one-shot injection knob is armed, not in effect, when the write returns

`dl_inject_hb_pause_ms` (and every knob shaped like it) is read at the **top of
the worker's loop** and cleared there. Writing the sysfs file only leaves a
value for the worker to pick up on its next pass.

The lap this bit: the barrier harness arms a 12 s heartbeat pause and then asks
the barrier whether it waits for a beat **issued after the call**. If the
heartbeat thread was already mid-beat when the knob was written, that beat
completes in milliseconds, satisfies the barrier, and the arm reports
`wait_ms≈0` — a FAIL against an implementation that is perfectly correct. The
pause then starts, after the measurement, and affects nothing.

The fix is one poll, and it costs at most one worker interval:

```
echo $pause > $PAUSEKNOB
i=0; while [ $i -lt 30 ]; do
    dmesg | sed -n "/$MARKID-$name/,\$p" | grep -aq 'P-HB-INJECT-PAUSE' && break
    i=$((i+1)); sleep 0.2
done
echo PAUSE_POLLS=$i
```

Then the same line doubles as the arm's **vacuity guard**: if it never appears,
the knob was not taken and the arm measured a healthy cluster twice — exit
VACUOUS rather than report a PASS.

Two general rules from it:

1. An injection is in effect when the MODULE says so, never when the write
   returns. If the injector has no log line, add one before using it as a
   measurement.
2. Scope the poll to this lap's kernel-log marker. The ring survives module
   reloads, so an unscoped grep matches a previous lap's injection and the
   harness proceeds against a knob that was never taken this time.
