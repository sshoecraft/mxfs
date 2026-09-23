---
name: technique-decompose-a-held-barrier-with-its-own-timing-line-before-arguing-about-which-part-to-move
description: TECHNIQUE (sess40, D-0962/0967): P-COMPLETE-RETIRE-TIMING's per-step fields summed to the observed 94.26 s exactly, which showed the 104 s "takeover…
metadata:
  type: feedback
tags: [method, measurement, dlm, recovery, D-0962, D-0967]
---

# Decompose a held barrier before arguing about which part to move

`P-COMPLETE-RETIRE-TIMING` already carried `refresh_ms / ledger_ms /
dlmpurge_ms / handoff_ms`, and those plus the following `disklock_purge_ms`
summed to the observed replay→P163 gap to within a few ms:

```
1 + 22443 + 0 + 71148 + 640 = 94.23   vs  94.26 s measured
```

That single sum did three things no amount of reading could:

- It proved which step owned the wall (the takeover, 71 of 94 s) instead of
  assuming the defect's own summary was complete.
- It revealed a SECOND serial per-page pass nobody had named — a 22.4 s
  whole-ledger purge — which became its own defect record instead of being
  silently absorbed into the first one's "fix".
- It predicted the fixed arm's result (≈23 s at that residue, 14.92 s at half
  the residue) before the lap ran, so the arm CONFIRMED a number rather than
  discovering one.

## The trap it avoids

A fix that removes the biggest term leaves the rest, and a harness whose single
assertion spans the whole barrier then fails and looks like the fix did not
work. That is the moment where a threshold gets widened. Don't: split the
assertion so each one names the defect that owns it, and file the remainder
with its measurement. Here the fixed arm asserts `handoff_ms` (what the change
owns, and what was never asserted before) and merely REPORTS the total gap with
a note attributing it to the other record.

## Scope a log-derived number to the identity it belongs to

The same lap's harness took its page counts from `tail -1` on
`P-TAUTH-TAKEOVER`. The lap ends with a cold remount, and the new incarnation
then takes over its OWN predecessor's pages — a second, larger line in the same
window. The harness reported `cand=2953 total_ms=29197` from the wrong pass
while the pass under test was `cand=2703`. Anchor on the identity: the victim's
node id is on the completion's own timing line, so grep
`departed=<victim>/`, and include the `-INTERRUPTED` variant, because a pass
that stops between pages is still the pass you are measuring.

## A pass that returns early prints no summary

`rc=-4` (`-EINTR`) with no `P-TAUTH-TAKEOVER` line looked like the deferral had
silently skipped the work — the exact failure mode the defect record warned
about. It had not: the lap's own cold remount set `shutting_down`, the pass
stopped between pages by design, and the next incarnation drained the rest.
Before concluding "the work was skipped", find the early-return path's own
line; every one of them has one.
