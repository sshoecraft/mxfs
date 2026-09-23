---
name: fable-safeguard-refusal-fallback-to-opus-mechanism
description: Why sessions "switch to Opus 4.8"/die with "[cyber]": API safeguard flag + CLI refusal-fallback. Not CLAUDE.md/RULE 10/agents. Rate spiked 2026-08-22.
metadata:
  type: reference
tags: [claude-code, ccloop, opus-fallback, safeguards, cyber, reasoning_extraction, switchModelsOnFlag]
---

# Fable 5 safeguard refusals → Opus fallback / session death

Investigated 2026-08-22 (user saw switches/stalls; by 15:18Z the rate was 4 refusals in 25 min).

## Mechanism (read from the CLI binary, `~/.local/share/claude/versions/2.1.239`)
- Anthropic's API-side safeguard classifier returns `stop_reason: refusal` with a category: `cyber`, `bio`, `frontier_llm`, `reasoning_extraction`. It fires mid-stream: transcripts show a thinking block emitted, then the refusal 3-20 ms later — i.e. it scans Fable's OUTPUT (real-time cyber safeguards), not only the prompt.
- CLI hardcoded per-category fallback table: `cyber → claude-opus-4-8` (all variants); `bio → opus-5 or opus-4-8`; `reasoning_extraction` has NO entry → `model_refusal_no_fallback` → API-error text "try a different model with /model".
- `gnm()` treats `claude-fable-5` AND `claude-opus-5` as the same refusing class (Opus 5 got the cyber safeguards ~early Aug), so cyber routes to 4.8. CLI 2.1.220 (Jul 26/Aug 1/Aug 2) routed to Opus 5; 2.1.224+ (Aug 7 on) routes to 4.8.
- Gate `switchModelsOnFlag` (settings.json, default true): true → silent auto-switch and the REST OF THE SESSION runs on Opus (200-300 turns each time in July/Aug; 49 turns + a code edit on 4.8 in sess386). false → CLI shows a dialog and PARKS the session waiting for a human (sess389 sat 3.5 h+, nothing written to the jsonl — the park precedes the row).
- `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` (now in `~/.claude/settings.json` `env` block, set 2026-08-22 11:5xZ) → no switch, no dialog; the turn ends with the API error (`model_refusal_no_fallback`, requestId logged). Under ccloop the refusal ENDS THE SESSION and ccloop rolls to a fresh one (orientation ramp each time): sess392 bb5fe4fa died 14:58Z after 2 refusals, sess393 21808c3f 15:09Z (64 turns), sess394 c8c40ec3 15:18Z (36 turns).
- `CLAUDE_CODE_REFUSAL_FALLBACK_CATCH_ALL` enables fallback for unmapped categories. Dialog park timeout: `CLAUDE_CODE_USER_DIALOG_TIMEOUT_MS`.
- Evidence rows: `type:system, subtype:model_refusal_fallback|model_refusal_no_fallback` with `apiRefusalCategory` + `requestId`; assistant content block `{"type":"fallback","from":..,"to":..}` marks a switch.

## History in this project (all `cyber` unless noted)
Jul 26, Aug 1 (sess22), Aug 2 (sess25) → Opus 5 silently; Aug 7 (sess148) → Opus 4.8 silently; Aug 22 01:15Z sess386 → Opus 4.8; 01:57Z sess386 `reasoning_extraction` (req_011CeGxTh4cVQhkTw9tKpSTf; first Fable "continue" after 49 Opus turns were in context); ~08:08Z sess389 parked on dialog; 14:56Z + 14:57Z sess392 (req_011CeHysKkzH5QUnxz9ijCNz, req_011CeHyw5zcqNmadnWEiv5ND); 15:09Z sess393 (req_011CeHzoY8tFeFeAF7CJ2wQb); 15:18Z sess394 (req_011CeJ1XNDkHn95g2vofAaFv).

## Ruled out as the trigger (evidence)
- CLAUDE.md: identical across ~1,500 clean Fable requests and the flagged ones.
- RULE 10 / subagents: the Jul-Aug 7 and sess386/389 events had ZERO Agent calls. After ccenv 0.23 made sessions delegate (sonnet grind/scout; NOTE log-sweeper ran on claude-opus-5 in sess393), sess394 was refused with ZERO agents — flags happen with and without subagent output in context.
- GPT consults, ccloop prompt vocabulary (same fence/kill/wedge words for weeks; "overflow" never in any prompt).
- With constant inputs the rate went 3 in 3 weeks → 3 in 24 h → 4 in 25 min: server-side classifier change.

## What to do
1. Cyber Verification Program: https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude — the only lever on the flag rate.
2. Keep auto-switch OFF for unattended runs (Opus turns in context set up `reasoning_extraction`; Opus-authored edits land unreviewed).
3. ccloop should treat `model_refusal_no_fallback` as retryable IN THE SAME SESSION (resume + "continue") rather than rolling over to a fresh session; the flag is stochastic per request.
4. `/feedback` with the requestIds above.
