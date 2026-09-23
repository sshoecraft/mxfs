---
name: trap-a-poll-helper-whose-bound-is-in-seconds-read-as-a-poll-count-manufactures-a-liveness-fail
description: TRAP (s74, fence_lost_response): wait_for_into's 3rd arg is SECONDS (it sleeps 2 and adds 2), not a poll count; PROGRESS_BOUND/5 gave a 48s wait for…
metadata:
  type: feedback
tags: [harness, rig, liveness, rig.sh]
---

# `wait_for_into <var> <node> <bound> <mark> <pattern>` — `<bound>` is SECONDS

`tests/lib/rig.sh:247`. The loop is:

    while [ "$wfi_i" -lt "$wfi_bound" ]; do
        ... poll ...
        sleep 2
        wfi_i=$((wfi_i + 2))
    done

so the counter accumulates **seconds**, not iterations. `wait_for_into lost "$A" 110 ...`
in `fence_crash_cuts.sh` means 110 seconds.

## What it cost

Writing `tests/fence_lost_response.sh` I passed `$(( PROGRESS_BOUND / 5 ))`,
reading the argument as a poll count and dividing a 240 s budget down to "48
polls". It is 48 **seconds**. The event being waited for — the fencing
re-drive picking up a released sole-survivor gate — runs on a 60 s sweep, so
the wait would have expired before the first opportunity and the harness would
have printed a liveness FAIL ("no certificate within the bound … blocking past
the point where the proof exists is a liveness failure") about a module that
was behaving correctly.

Caught by reading the helper instead of trusting the name, with the lap already
running; the lap was killed rather than measured against a bound known to be
wrong. Do not edit a shell script while bash is executing it — kill first, then
edit.

## The general shape

A harness that waits for an event must derive its bound from the **period of
the mechanism that produces the event**, not from a round number, and must
state that derivation next to the wait. Here: the re-drive sweep is 60 s and
`fence_blocked_after_ms` is 120 s, so anything under one sweep manufactures a
failure and anything over the blocked transition measures a different state.

A wait that is too short does not read as "no measurement". It reads as a
confident negative verdict about the filesystem.
