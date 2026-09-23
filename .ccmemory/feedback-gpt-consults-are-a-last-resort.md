---
name: feedback-gpt-consults-are-a-last-resort
description: USER (2026-09-04): stop calling GPT continuously, but do not swing to never. RULE 5 rewritten to a middle setting; an Opus-fallback session may consu…
metadata:
  type: feedback
tags: [feedback, gpt, rule-5, consult]
---

# GPT consults: a middle setting (user directive, 2026-09-04)

User, watching the session: *"Every time I look at your session you're calling GPT, which is over the top. You're Fable 5.1. Why are you having to depend on GPT so much? If you're gonna quote CLAUDE.md then change it."*

Then, on the first rewrite (which made it a strict last resort): *"when my Fable tokens run out, I need to use Opus, right? And that means it may need to ask GPT every now and then for a consult. So going from never asking or always asking to never asking is not an option. ... try not to go from one extreme to another."*

Root of the behaviour: the sess29 RULE 5 wording ("default to consulting GPT", "consult BEFORE, not only when stuck", "before implementing any non-trivial fix") made the consult a routine step of every loop.

RULE 5 in CLAUDE.md now (rewritten with the user's authorization, same turn):
- consult when the user asks; when a hard-to-reverse design choice (on-disk format, wire protocol, fencing/recovery semantics, durability contract) has more than one plausible shape; when a RULE 4 loop has not converged after two build/deploy cycles;
- a session running on a model below Fable (Opus fallback) consults more readily on those cases and may ask before a fix touching DLM, replay or fencing paths;
- not to review an analysis already made, pick the next defect, sanity-check an instrument-proven fix, or before a small reversible change; one consult per question; measurements outrank the reply.

Call mechanics (no `model`, no `max_tokens`) unchanged.
