---
name: feedback-handoff-state-via-relay-and-ccmemory-never-claude-md
description: Session handoff/state goes via the ccloop relay (auto system-prompt) + ccmemory ONLY. NEVER put rolling state/build/findings in CLAUDE.md, a STATE.md…
metadata:
  type: feedback
---

## Where session handoff/state belongs (user directive, sess46 ccloop, emphatic)

**Handoff = the ccloop relay (automatic) + ccmemory. Nothing else.**

- **ccloop relay**: when context fills, the wrapper summarizes the transcript into
  the NEXT session's system prompt (the "Resume — run …" block). This is the
  primary handoff channel. You do not write or manage it — it happens automatically.
- **ccmemory**: write a NEW `sessNN-*` memory each session for durable findings /
  current-blocker / next-steps. New file each time (do NOT append to a rolling file
  — that just becomes a changelog).

**NEVER do these (all corrected in sess46):**
- ❌ Do NOT put rolling state in `CLAUDE.md` (build srcversion, current blocker,
  what you proved/refuted, next steps, per-session findings). CLAUDE.md is STABLE
  rules + architecture + routing ONLY. A prior convention had bloated the
  `[AWARENESS]` "current build" bullet into a single ~34 KB line that every
  session then paid to load — archived to `.claude/awareness/build-history.md`
  and removed. Do NOT recreate it.
- ❌ Do NOT invent a `STATE.md` (or any hand-rolled rolling state file). It becomes
  a changelog and duplicates the relay + ccmemory.
- ❌ Do NOT use `CHANGELOG.md` for troubleshooting/handoff notes. CHANGELOG.md is
  for product/version-to-version changes ONLY.

**Why:** the relay already carries state and ccmemory already carries durable
notes. Anything in CLAUDE.md is pure redundancy that bloats the always-loaded
instructions for every future session. The sess46 mistake was COPYING the
inherited "update the CLAUDE.md awareness head" ritual without noticing it
duplicated a mechanism that already exists. Don't follow an inherited convention
that conflicts with this — this directive wins.

**How to apply:** at session end / before a context handoff: (1) write a fresh
`sessNN-*` ccmemory with the state; (2) let the relay do the rest; (3) leave
CLAUDE.md untouched unless you are changing a STABLE rule/architecture fact.
The awareness-protocol line "update awareness docs before handoff" refers to the
STABLE subsystem/structural docs — NOT to session state. Do not conflate them.
