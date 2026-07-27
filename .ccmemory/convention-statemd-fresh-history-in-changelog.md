---
name: convention-statemd-fresh-history-in-changelog
description: USER CONVENTION (emphatic): state.md = CURRENT handoff snapshot ONLY, written FRESH (overwritten) each handoff — never prepend/accumulate. Project/se…
metadata:
  type: feedback
tags: [user-directive, convention, context-handoff, state.md, changelog]
---

# state.md is a fresh snapshot, not a history log — history → CHANGELOG.md

User directive, 2026-07-20, emphatic ("state.md is NOT for history!! history
belongs in CHANGELOG.md!!!").

## The rule

- **`state.md` = the CURRENT handoff snapshot ONLY.** On every context handoff,
  write a **NEW** `state.md` (overwrite it completely). Do NOT prepend a new
  section on top of the old one. Do NOT accumulate prior sessions' sections in
  it. It should contain only: what this session did, current code/deploy state,
  open bugs, next steps, and the gotchas the next session needs — nothing older.
- **Project/session HISTORY belongs in `CHANGELOG.md`**, not `state.md`. If a
  session's accomplishments should be preserved as history, they go there.

## Why this corrects prior behavior

The pre-existing `state.md` had grown to 865+ lines by PREPENDING each session's
state on top of all prior sessions (SESS8/9/10/11 ledgers, etc.). That is wrong
per this directive — the handoff skill's default "prepend/keep history" behavior
must be overridden for THIS project: overwrite state.md fresh, and route any
history worth keeping to CHANGELOG.md.

## Applies to

The `context-handoff` skill (and any manual handoff): Step 2 "write the state
file" = write a FRESH state.md, do not append to the existing one.
