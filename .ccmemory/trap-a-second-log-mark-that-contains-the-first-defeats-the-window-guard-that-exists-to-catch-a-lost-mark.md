---
name: trap-a-second-log-mark-that-contains-the-first-defeats-the-window-guard-that-exists-to-catch-a-lost-mark
description: TRAP (s137): the park mark was the window mark plus "-PARK", so window_into's substring guard matched the wrong line and a 55 s-late window was grade…
metadata:
  type: feedback
tags: [measurement-integrity, harness, dmesg, ring-buffer, rig]
---

# A second mark that contains the first turns the window guard into a no-op

Measured s137 from lap `s133b`
(`tests/parked_log_waiter_across_closure.sh`, 2/tcp, build
`F3199FE2112E215C2FBB787`).

`tests/lib/rig.sh`'s `window_into` captures a node's kernel log from a mark:

```sh
measure ... "dmesg | sed -n \"/$wi_mark/,\\\$p\"; echo WINDOW_END"
if ! grep -qaF -- "$wi_mark" "$wi_f"; then
    echo "ABORT: ... the ring wrapped or the mark was never written ..."
```

That guard is the whole safety net: it is what stops a lap counting probes in a
window that no longer reaches back to the instant it claims to start from.

The harness wrote **two** marks — `PLW-MARK-$LABEL` at the arm, and
`$MARK-PARK` at the heartbeat park — and scoped the window with the first. The
park line *contains* the first as a substring, so:

- `sed` found the park line when the arm line was gone from the ring, and
- `grep -qaF "$MARK"` matched that same park line, so the ABORT never fired.

The window silently opened **55 s late**, at ring time 250.9, and every count
taken from it was a count over the wrong interval. The injector's own
confirmation (`P-DBG-AUTH-PUMP-PAUSE`, fired within ~250 ms of arming) read 0,
so the subject arm failed its arming assertion for a reason unconnected to the
thing it was arming — and the `P290-AUTH-CLOSED` count the verdict rested on was
equally unestablished.

## Two rules this leaves

1. **No mark may be a prefix or substring of another mark in the same lap.**
   Not `X` and `X-PARK`. Give the second a name of its own (`PLWPARK-$LABEL`).
   A guard that matches by substring cannot tell them apart, and the one it
   cannot tell apart is exactly the case it exists to catch.
2. **Read an injector's confirmation AT THE ARM, not from the end-of-lap
   window.** The knob reading back is the value being *stored*, not the module
   having *taken* it. A confirmation counted at the end has to survive the whole
   workload's log volume in the victim's ring; under a log-filling workload it
   does not. Poll for the module's own line under a bound derived from the
   mechanism's cadence, and make its absence an ABORT rather than a verdict —
   an arm that cannot show it armed has measured nothing.

Related and the same family: `trap-a-kernel-log-mark-named-for-the-arm-and-not-for-the-lap-replays-the-previous-laps-verdict-to-the-millisecond`,
`trap-a-substring-contamination-test-matches-the-transports-routine-peer-death-deferral-line-and-aborts-every-lap`.
