---
name: rules-9-10-batching-delegation-and-what-fable-refuted
description: RULES 9 (batch side-effect-free calls; verified 3 Reads = 1 request) and 10 (delegate grind to sonnet/haiku, cap+instrument reports) landed. RULE-5 r…
metadata:
  type: project
---

# RULES 9/10 landed; 500k cutoff REJECTED on review (2026-08-15)

Follows `quota-is-fable-REQUESTS-not-tokens-4430-per-week`.

## Verified this session

- **A multi-tool response bills as ONE request.** Three `Read` calls in one
  response = one requestId. RULE 9's premise. Was untested before.
- **Subagent model override works.** `model: sonnet` subagent → 3
  `claude-sonnet-5` requests; `model: haiku` → 9 `claude-haiku-4-5`
  requests; parent stayed `claude-opus-5`.
- Fleet is 32/32 up on 0.14.1 `BDEB75D40B5BE7C21C82EF6` (NOT the 0.14.2
  closure-purge build).

## NOT verified — do not build on these

1. **Pool accounting from a FABLE parent.** The experiment's parent was
   Opus. Model *attribution* ≠ pool *debit*. Test before trusting RULE 10
   in the loop.
2. **Whether sonnet/haiku have their own exhaustible pools.**
3. **Fallback when a subagent model is unavailable** — does the work
   silently land on the metered pool at full price? Unattended loops
   don't notice.

## §5 REOPENED: output tokens vs requests

Cutting the window slashes cache-read but barely touches output/response.
So output-token metering produces the SAME signature.

| metric | CV over 4 exhaustions |
|---|---:|
| fable requests | 3.94% |
| fable output tokens | 8.54% |

Variance ratio 4.71, **F(3,3) — not significant at n=4.** The earlier
"output is just a proxy" dismissal was too confident.

**RULE 9 survives either way**: batching removes 2 responses' worth of
thinking (~94% of output) while the tool_use payload is unchanged, so it
cuts output tokens too. **The cutoff change does NOT survive** — raising
the window only pays under request metering.

## 500k cutoff REJECTED (was recommended earlier in the same session)

- Requests/closure is flat across every config ever run (678/601/751) — by
  the headline metric the cutoff is not a lever in either direction.
- The 3.63→1.99 req/productive-action curve is confounded by **session
  phase**: high-peak sessions are LONG sessions, which are ones that had
  productive work and had already amortised setup. Selection, not
  causation — same error class as the token-weighting assumption.
- Asymmetric risk: degraded long-context recall on a codebase where a wrong
  edit corrupts a filesystem.
- If run: pre-registered, metric fixed in advance, alternating weeks, NOT
  in the same commit as RULES 9/10.

## The sharpest review catch (now in RULE 10)

**A capped report makes the WEAKER model select which evidence survives,
and selection is a conclusion wearing evidence's clothes.** Verbatim
`file:line` excerpts look RULE 6-compliant while silently omitting the line
that mattered. Worst case is negatives: haiku's "no matches" (wrong regex?
wrong subtree?) becomes an evidence-backed "defect not present".
Mitigations written into RULE 10: report exact commands + **pre-truncation
totals**; re-verify disposition-critical negatives in the parent; a
subagent may NEVER widen or retry a timed-out run (RULE 0) — a helpful weak
model re-running a flaky test until green launders a defect away.

Also: every agent definition must embed RULES 0/2c/3 verbatim — subagents
inherit nothing from CLAUDE.md, and a haiku agent running `pgrep -f` wedges
clyde unattended.

## Open items worth more than any of this
- **Post-exhaustion behaviour**: what does the loop do for the 3-5 days
  between exhaustion and Thursday reset? If "nothing", that dwarfs every
  lever here.
- **Restart economics as a line item**: sessions/week × ~5-request ramp.
- Audit CLAUDE.md for every rule motivated by TOKEN cost — all are now
  candidates for reversal.
