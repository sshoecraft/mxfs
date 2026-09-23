---
name: trap-a-probe-format-change-is-the-only-way-to-tell-which-build-a-dmesg-line-came-from
description: TRAP (sess565): a live-dmesg grep counted 45 probe lines as if they were the new build's; they were the previous build's, same boot. Field presence d…
metadata:
  type: feedback
tags: [trap, dmesg, harvest, instrumentation, d0924]
---

# A dmesg harvest is scoped by the BOOT, not by the module load

sess565, hunting D-0924. The probe `P-AGMETA-RELSE-OUTSTANDING` was refined
between 0.75.94 and 0.75.95 so it would only fire from a caller that cannot be
followed by a completion. The obvious verification — grep the live `dmesg` on
both nodes for the probe and count non-`iodone` firings — returned **45 hits on
test2**, which reads like a loud confirmation that the uncovered route is being
taken constantly.

It was the opposite. Those 45 lines were at uptime 600–612 s, printed by the
**0.75.94** build earlier in the same boot. `rmmod`/`insmod` does not clear the
kernel ring, so every probe line every build printed since boot is still there,
and a `grep -c` over live dmesg counts all of them as if they were the current
build's.

## What actually discriminates

Not the timestamp (you would have to know when the module was reloaded), and
not the count. **The message format.** 0.75.95 added a `why=` field; 0.75.94's
line has none. So:

    dmesg | grep P-AGMETA-RELSE-OUTSTANDING | grep -c "why="

is 0 on both nodes, and that is the real reading — the new probe never fired.
Per-lap windowed captures (`dmesg | sed -n '/$MARKER/,$p'`) agreed: 0 in all six
node-captures across three laps.

## The rule this earns

When you change a probe's condition, **change its printed fields too**, even
trivially. The format then carries the build identity, and any later harvest —
yours or a subagent's — can separate old lines from new without knowing the
reload time. A probe whose message is byte-identical across two builds is
unfalsifiable from a ring buffer.

Corollary for delegation: a subagent asked to "grep dmesg and count X" will
faithfully return a number that is confounded, because the confound is invisible
in the command. Ask it for the **format-discriminating** count, or point it at
the per-lap evidence captures instead of live dmesg.

## Also true here

`grep -o "why=[a-z-]*" | sort | uniq -c` over the whole ring greps *every*
subsystem's `why=` field (depart, durable, periodic, removed, …), not the
probe's. Scope the grep to the tag first, then extract the field.
