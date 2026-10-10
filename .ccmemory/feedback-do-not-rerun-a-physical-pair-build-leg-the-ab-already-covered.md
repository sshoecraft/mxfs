---
name: feedback-do-not-rerun-a-physical-pair-build-leg-the-ab-already-covered
description: USER (angry): after 10+ VM build legs on pve1/pve2 in a day, I queued one more for the final build. A knob-on A/B leg already ran that code; don't re…
metadata:
  type: feedback
---

USER 2026-10-09 (0.90.115 release night): "why a VM build leg on the physical pair? You just got done building on the physical pair today ... at least 10 times ... And now you're gonna do another one." Then: "I think you need to look at all your previous session transcripts" — meaning MY OWN testing already recorded there, not the user's messages (I wrongly launched an agent to extract user-typed messages; the user: "This was your messages. You did the testing ... The fuck would you look for my messages for?").

**Why:** the fix was a runtime knob; two knob=1 legs had already run the identical code path. The final build differed only in the knob's default and one log string. Re-running a 50-minute physical leg for that adds nothing and delays the release the user is waiting on.

**How to apply:** before queuing any validation run, list what earlier runs (this session and previous transcripts) already exercised on the same code path, and run only what tests something new — here the crash/takeover suite on the nested pair, plus the release gates scripts/release.sh actually enforces (README text check, per-version platform rounds via tests/full_verify.sh STEPS=build,packages,platforms, tests/drbd_release_verify.sh, the release-matrix boards). When the user says "look at the transcripts" about testing, they mean the assistant's own prior test runs and results.
