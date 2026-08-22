---
name: fable-safeguard-refusal-fallback-to-opus-mechanism
description: Why sessions "switch to Opus 4.8": Anthropic API safeguard flag (cyber/reasoning_extraction) + CLI refusal-fallback routing. Not CLAUDE.md, not RULE…
metadata:
  type: reference
tags: [claude-code, ccloop, opus-fallback, safeguards, cyber, reasoning_extraction, switchModelsOnFlag]
---

# Fable 5 → Opus 4.8 "switches" are API safeguard refusals + CLI fallback routing

Investigated 2026-08-22 after the user saw 3 switches/stalls in 24 h (ccloop run c7ee71c6 sess386 twice, sess389 once).

## Mechanism (read from the CLI binary, `~/.local/share/claude/versions/2.1.239`)
- Anthropic's API-side safeguard classifier returns `stop_reason: refusal` with a category: `cyber`, `bio`, `frontier_llm`, `reasoning_extraction`.
- The CLI has a hardcoded per-category fallback table: `cyber → claude-opus-4-8` (all variants); `bio → opus-5 or opus-4-8`; `reasoning_extraction` has **no entry** → `model_refusal_no_fallback` → API-error text "try a different model with /model".
- `gnm()` treats `claude-fable-5` AND `claude-opus-5` as the same refusing class, so cyber routes to 4.8, not 5 — Opus 5 would refuse the same request.
- Gate: `switchModelsOnFlag` (settings.json, default true). true → silent auto-switch ("Switched to Opus 4.8 … [cyber]") and subsequent turns run on Opus. **false → CLI shows a dialog and PARKS the session waiting for a human** (`tengu_refusal_fallback_prompt_shown`). Under unattended ccloop that is a stall (sess389 sat 3.5 h+ with no transcript rows after the flagged tool result — the park happens before any row is written, so the event is invisible in the jsonl).
- `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` → no switch, no dialog; the turn ends with the API error; ccloop keepgoing re-sends `continue`; the classifier is stochastic so the retry normally passes.
- `CLAUDE_CODE_REFUSAL_FALLBACK_CATCH_ALL` enables fallback for unmapped categories.
- Transcript evidence rows: `type:system, subtype:model_refusal_fallback|model_refusal_no_fallback` with `apiRefusalCategory` + `requestId`; assistant content block `{"type":"fallback","from":..,"to":..}` marks the switch.

## History in this project
- cyber → Opus 5: 2026-07-26, 08-01 (sess22), 08-02 (sess25) on CLI 2.1.220.
- cyber → Opus 4.8: 08-07 (sess148, CLI 2.1.224), 08-22 01:15Z (sess386). 08-22 ~08:08Z sess389 parked on the dialog (category unknown).
- reasoning_extraction (no fallback): 08-22 01:57Z sess386, req_011CeGxTh4cVQhkTw9tKpSTf — the first Fable "continue" after the session had run 49 turns on Opus 4.8 (harness-injected other-model turns in context = the shape that category targets).
- All flagged requests were plain Fable turns doing dmesg/fence/death-event analysis. ZERO Agent/subagent calls in any flagged session; CLAUDE.md identical across ~1,500 clean Fable requests and the flagged ones; ccloop session prompts carry the same vocabulary as prior weeks. RULE 10 delegation, GPT consults, and CLAUDE.md edits are all RULED OUT as the trigger. The rate change (3/24h vs 3/3weeks with constant inputs) is server-side.

## What to do
1. Cyber Verification Program: https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude — the only lever on the flag rate.
2. For ccloop: `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` so a flag errors-and-retries instead of switching to Opus or parking on a dialog.
3. `/feedback` with the requestIds.
4. Never re-enable auto-switch for unattended runs: Opus turns in context set up the reasoning_extraction refusal on hand-back, and Opus-authored code edits land in the tree unreviewed by the session model.
