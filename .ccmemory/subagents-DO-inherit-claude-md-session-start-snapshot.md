---
name: subagents-DO-inherit-claude-md-session-start-snapshot
description: VERIFIED 2026-08-15: subagents DO inherit CLAUDE.md (haiku agent listed RULES 0-8 verbatim, zero tool calls) — but the SESSION-START snapshot: rules…
metadata:
  type: project
---

# Subagents inherit CLAUDE.md — but the session-start snapshot

**Test (2026-08-15):** spawned a `general-purpose` subagent with
`model: haiku`, instructed it to use NO tools and report only what was
already in its context.

**Result — inheritance CONFIRMED:**
- Listed RULES 0, 1, 2, 2b, 2c, 3, 4, 5, 6, 7, 8 with correct summaries,
  including the unusual 2b/2c numbering.
- Answered yes to all four specific prohibitions probed (`pgrep -f`,
  host reboot, derived timeouts, scripts-in-tree).
- Quoted this file's opening line verbatim.
- **`tool_uses: 0`** — it did not read the file. Real inheritance, not
  reconstruction.

**The catch — it is the SESSION-START snapshot:** it did NOT list RULES 9
and 10, which had been added to CLAUDE.md earlier in that same session. So
a rule written today does not reach subagents until the next session
starts. Same for `.claude/agents/*.md` definitions — those register at
session start too (confirmed separately: newly written `rig-runner` /
`log-sweeper` types were "not found" until restart).

## Why this memory exists

A RULE-5 review asserted "subagents don't inherit house rules unless the
agent definition carries them" and called it the most dangerous omission in
the proposal. That assertion was written into CLAUDE.md **unverified**, as
"A subagent inherits none of this file." It is false, and it was caught
only because the user asked "will the subagents get the rules?" — which
prompted an actual test instead of another assertion.

**Lesson: a consult's claims are hypotheses, not findings.** The same
session had already been burned three times by publishing conclusions
ahead of testing them (300k -> 500k -> 145k on the cutoff). Test the cheap
ones; they are usually one subagent call away.

## Standing guidance (now in RULE 10)

Still embed RULES 0, 2c, 3 verbatim in every agent definition — not
because inheritance fails, but because a newly-written rule has not
propagated yet, and a constraint next to the task is obeyed more reliably
than one 400 lines up the file.
