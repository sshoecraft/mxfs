---
name: feedback-never-consult-another-model
description: USER 2026-10-06: never consult another model — no ask_gpt, ask_astra or ask_fable, on any model, even when stuck. CLAUDE.md RULE 5.
metadata:
  type: feedback
tags: [consult, gpt, astra, user-correction]
---

User, 2026-10-06 (0.90.71), after a session sent GPT a design question on recovering a withdrawn DRBD mount. First: *"ok stop asking gpt its actually dumber than you now. if you absolutely MUST ask someone (because you are stuck) then ask astra but it's expensive ... change it now and don't ask GPT anything anymore."* Minutes later: *"Actually, you need to do some web searching on opus 5.5 vs astra/gpt 5/etc ... it appears opus 5.5 (you) on max is the top ... So, honestly, don't ask anybody anything."*

The web check that turn backed this up for this project's work. Per vellum.ai and benchlm.ai, Opus 5.5 leads GPT-6 Astra on agentic coding (Terminal-Bench 4.0: 66.4% vs 57.9%) and full-repository coding (FrontierCode 54.4% vs 53.3%). Astra leads on advanced math, abstract reasoning and computer use.

The rule (CLAUDE.md RULE 5, rewritten that turn with the user's authorization):
- Never call `mcp__ask_gpt__query`, `mcp__ask_astra__query` or `mcp__ask_fable__query`. That holds on any model and for any question, including a hard-to-reverse design and a stuck loop.
- Own the decision: read the code and the references, instrument, measure.
- Stuck means the next step is a new instrument or a new hypothesis. A blocker only the user can clear is reported as one.

**Why:** two corrections on 2026-09-04 did not stick, because RULE 5 kept a design-choice clause that sessions treated as permission.
