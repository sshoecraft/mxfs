---
name: compiled-ccloop-relay-cutoff-no-handoff-file-and-ccmemory-hard-stop
description: ccloop session mechanics: plan against the run's cutoff file, never write a handoff file, and treat ccmemory being unavailable as a hard stop.
metadata:
  type: feedback
tags: [compiled, ccloop, relay, handoff, ccmemory]
---

# ccloop session mechanics: budget, handoff, and memory availability

Three behavior notes about how a ccloop-run session starts, ends and depends on ccmemory. They share one theme: the loop's real boundaries are not the ones the tooling displays, and the transcript plus ccmemory are the only continuity mechanisms.

## Budget: the relay fires at the run's cutoff file, not at the context window

From [[trap-the-ccloop-relay-fires-at-the-runs-cutoff-file-not-at-the-context-window-so-read-it-at-session-start]]:

- The context tool showed 46% of a 1M window used, which reads as plenty. `.ccloop/runs/<run-id>/cutoff` held `500000`, and `hook-events.log` showed the previous session `fired` and `halt` at exactly that number. The session had about 40K tokens left, not 540K, when it found out. That was after a 348 s module build and a deploy, with rig verification still to launch.
- At session start read `.ccloop/runs/$CCLOOP_RUN_ID/cutoff` and plan against that number. Orientation (memory list, prior transcript digest, files that must be understood) measured about 150K.
- Spend the first half of the budget on the code change and start the build early. A header change in `dlm/dlm.h` or `dlm/disklock.h` rebuilds most of the module (348 s measured), and the build can run while tests are written.
- Anything that must outlive the session is launched `nohup setsid`, with output and a one-line-per-step summary under `tests/evidence/`. The next session reads files instead of re-running. A background Bash task dies at the relay.
- Keep tool output small from the first call. Every large Read is paid for against the 500K, not the 1M.

## Handoff: there is no handoff file

From [[handoff-md-removed-context-is-auto-derived]] (user directive):

- ccloop derives the next session's starting context automatically from the transcript. Every mention of a handoff document was removed from ccloop, and the old CLAUDE.md rule that required maintaining `handoff.md` was deleted. The resulting numbering gap is deliberate; do not renumber.
- Do not create, write or update `.ccloop/handoff.md` or any equivalent (`state.md`, `HANDOFF.md`, `resume.md`, a session-summary file). Do not spend a turn on an end-of-session summary. The transcript is the handoff.
- This joins the earlier `state-md-deprecated-do-not-maintain` directive. The user has had to say it twice; do not introduce a third variant.
- Durable findings go to ccmemory. Defect state goes to the defect queue. Neither is a handoff document.

Together with the budget note: since the next session starts from the transcript, what must survive the relay is evidence files under `tests/evidence/` and lessons in ccmemory, not a hand-written summary.

## ccmemory unavailable is a hard stop

From [[feedback-ccmemory-unavailable-is-hard-stop]] (user directive):

- If ccmemory or the MCP interface exposing it drops or reports "disconnected" mid-session, stop. Report that ccmemory is unavailable and halt. This applies every time.
- A prior session saw the harness drop the MCP transport (ccmemory batched with several other servers) and concluded it was not a hard stop because the data is flat `.md` files on disk. The user explicitly overrode that conclusion.
- Reasons: memory is load-bearing for multi-session ccloop work. Without it prior lessons cannot be recalled reliably and solved problems get re-derived. The regen-index hook does not fire, so bypassing `memory_write` with direct file writes leaves `MEMORY.md` stale and risks silent divergence.
- Do not continue substantive work. Do not write memories by direct file write as a workaround and carry on. Do not declare "no memory loss."
