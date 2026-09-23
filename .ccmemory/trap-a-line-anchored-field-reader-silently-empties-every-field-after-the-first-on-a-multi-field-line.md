---
name: trap-a-line-anchored-field-reader-silently-empties-every-field-after-the-first-on-a-multi-field-line
description: TRAP (s87): the fence harnesses' field() anchored at ^, so an arm printing "SEEN=1 PAUSED=1" read SEEN and handed PAUSED "" — aborting healthy laps.
metadata:
  type: feedback
tags: [harness, measurement-integrity, rig]
---

# A `^`-anchored field reader empties every field after the first

Sixteen `tests/*.sh` fence harnesses carried the same helper:

    field(){ grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

The `measure` convention in these harnesses is to print several fields on ONE
line — `SEEN=1 PAUSED=1`, `PAUSEEND=0 WITHDRAW=0`. The anchor means only the
FIRST field on such a line is readable. Every later one comes back as the empty
string.

## Why it is worse than a wrong number

`ck` refuses to grade an empty value and aborts the lap:

    ABORT: 'B's proactive reservation-health check is held off' was asked to
    judge an EMPTY value (want=1): nothing was measured

So the symptom is a healthy lap aborting at an assertion about a subsystem that
was working perfectly — in s87a the arm HAD taken effect (`PAUSED=1` was sitting
in the capture file), and the run was thrown away anyway. The abort is correct
behaviour by `ck`; it is the reader that lied.

## The fix

    field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

Applied to all sixteen in 0.89.20. When adding a field to an existing arm's
print, check the reader can see it: a second field is invisible to an anchored
match, and nothing warns.
