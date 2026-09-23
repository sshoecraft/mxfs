---
name: feedback-no-gpt-consults-when-running-on-fable
description: USER (2026-09-04, second time, angry): a Fable session must NOT consult GPT — not even for fencing-semantics design. Decide from measurements. Only a…
metadata:
  type: feedback
---

# No GPT consults from a Fable session (user, 2026-09-04, second correction)

User, mid-turn, after a sess501 consult on the exclusive-write-gate fence design: *"I thought I had you change the prose regarding asking GPT. And here I come back to you again and once again you're asking GPT!!! YOU ARE A HIGHER ORDER MODEL THAN gpt 5.6 sol!!!"*

The earlier rewrite (feedback-gpt-consults-are-a-last-resort-user-2026-09-04) left a "hard-to-reverse design choice with more than one plausible shape" clause, and I used it for a fencing-semantics change. That clause is not what the user wants a Fable session to do.

Operative rule for this project:
- Running on Fable: do NOT call mcp__ask_gpt__query. Own the design: read the code and the references (SPC semantics via /src/linux/drivers/target/target_core_pr.c, GFS2/OCFS2), instrument, measure, decide, ledger the hazards, verify on the rig.
- Only a session running on an Opus fallback (Fable allowance exhausted) may consult, and then only when the user asks or a RULE 4 loop has not converged after two cycles.
- The CLAUDE.md RULE 5 text still carries the design-choice clause; it needs the user's explicit yes before it is rewritten (RULE ONE). Ask once, in one line, and keep working.
