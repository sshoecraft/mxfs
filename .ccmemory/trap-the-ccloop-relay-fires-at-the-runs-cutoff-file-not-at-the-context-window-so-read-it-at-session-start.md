---
name: trap-the-ccloop-relay-fires-at-the-runs-cutoff-file-not-at-the-context-window-so-read-it-at-session-start
description: TRAP: ccloop halts a session at .ccloop/runs/<id>/cutoff (500000 tokens), not at the 1M window; orientation alone costs ~150K. Read it first.
metadata:
  type: feedback
tags: [ccloop, context, relay, planning]
---

# The ccloop relay fires at the run's cutoff file, not at the context window

**What happened (0.90.21 session):** the context tool reported 46% of a 1M
window used, which reads as plenty.  `.ccloop/runs/<run-id>/cutoff` held
`500000`, and `hook-events.log` shows the previous session `fired` and `halt`
at exactly that number.  The session had 40K tokens left, not 540K, when it
found out — after a 348 s module build and a deploy, with the rig verification
still to launch.

**What to do:**
- At session start read `.ccloop/runs/$CCLOOP_RUN_ID/cutoff` and plan against
  THAT number.  Orientation (memory list, prior transcript digest, the files
  that must be understood) measured about 150K here.
- Spend the first half of the budget on the code change and get the build
  started early: a header change in `dlm/dlm.h` or `dlm/disklock.h` rebuilds
  most of the module (348 s measured), and the build can run while tests are
  being written.
- Anything that must outlive the session is launched `nohup setsid` with its
  output and a one-line-per-step summary under `tests/evidence/`, so the next
  session reads files instead of re-running (a background Bash task dies at
  the relay).
- Keep tool output small from the first call: every large Read is paid for
  against the 500K, not the 1M.
