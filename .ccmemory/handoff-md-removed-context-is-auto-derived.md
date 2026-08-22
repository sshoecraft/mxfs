---
name: handoff-md-removed-context-is-auto-derived
description: USER DIRECTIVE sess375: .ccloop/handoff.md is GONE — ccloop derives the next session's context from the transcript automatically. Do NOT create or ma…
metadata:
  type: user
---

# No handoff file. Ever.

**User directive, sess375 (run c7ee71c6).**

ccloop no longer reads a handoff document, and every mention of one was
removed from ccloop itself. The next session's starting context is derived
**automatically from this session's transcript**. There is nothing for a
handoff file to do.

## What was removed

- `/src/mxfs/CLAUDE.md` **RULE 8 — MAINTAIN `handoff.md` AS YOU WORK** —
  deleted in full (2,389 bytes). The rule numbering now goes 7 → 9; that gap
  is deliberate, do not renumber.
- `/src/mxfs/.ccloop/handoff.md` — deleted.

## The rule now

- Do **NOT** create, write, or update `.ccloop/handoff.md` or any equivalent
  (`state.md`, `HANDOFF.md`, `resume.md`, a "session summary" file, …).
- Do **NOT** spend a turn writing an end-of-session summary for the next
  session. The transcript is the handoff.
- This joins the existing `state-md-deprecated-do-not-maintain` directive —
  same reasoning, different file. The user has now had to say this twice; do
  not reintroduce a third variant.

Durable findings still belong in **ccmemory** (that is what it is for) and
defect state still belongs in `tests/criteria/OPEN_DEFECTS.json` under
RULE 6. Neither of those is a handoff document.
