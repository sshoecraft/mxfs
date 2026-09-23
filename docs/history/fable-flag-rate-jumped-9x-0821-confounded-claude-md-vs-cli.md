<!-- Fable safeguard-flag rate: ~1/4,600 req (07-24..08-15) → ~1/500 (08-21/22). Window confounds CLAUDE.md the batching and delegation rules/2d+agents with CLI 2.1.239. A/B need… -->
# Fable flag rate analysis (2026-08-22, from all transcripts)

Per-day Fable requestIds vs flag events (system `model_refusal_*` rows, `fallback` blocks, plus the one PARK with no row):

| period | Fable reqs | independent flag events | rate |
|---|---|---|---|
| 07-24..08-15 (CLI .218-.233, CLAUDE.md pre-the batching and delegation rules/2d, no .claude/agents) | ~18,300 | 4 (07-26, 08-01, 08-02, 08-07 — all cyber) | ~1/4,600 |
| 08-15 20:53Z → 08-21 20:23Z | **0 — the loop ran claude-opus-5** (~2,800 req, 0 flags) | — | — |
| 08-21 20:23Z → 08-22 12:31Z (CLI 2.1.239, the batching and delegation rules/2d + agents present) | ~1,000 | 2 independent (01:15Z cyber; 08:08Z park) + 1 dependent (01:57Z reasoning_extraction = first Fable turn after 49 Opus-4.8 turns) | ~1/500 |

So the rate rose ~9×, and the window where it rose is exactly the first window in which Fable ran with the batching rule, the delegation rule, the guarded-host rule, docs/host-safety and `.claude/agents/{rig-runner,log-sweeper}.md` in its prompt — AND the first window on CLI 2.1.239. The two are perfectly confounded in the data; no Fable request exists with one but not the other (f80713d4 on .238 with the delegation rule but no 2d: 164 req, 0 flags — too small).

What is NOT supported: the delegation rule delegation as the mechanism. `Agent` tool calls since 08-10: only 5, all in the Opus-5 session 0dc8175e on 08-15/16. Zero in any Fable session, zero in any flagged session. Every flagged turn (all 6, 07-26→08-22) was a plain Fable turn whose last content was dense kernel forensics: dmesg ring dumps, fence/death tables, `/proc/kcore`+bpftrace+pahole notes (08-07), `UNHEALTHY shutdowns=18`, lap FAIL boards.

What IS supported from the user's reading: a model switch followed by a return to Fable DOES get flagged (01:57Z reasoning_extraction). That switch was the CLI's own cyber fallback to Opus 4.8 (switchModelsOnFlag was still true), not a subagent. `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` (live since sess390 12:17Z) removes that chain.

CLI 2.1.238→2.1.239 refusal-string diff: only `refusalFallbackLatchOriginRequestId` went 2→4 occurrences (latching logic), cyber=55 both, switchModelsOnFlag=23 both.

Proposed discriminating A/B (cheap: the delegation rule delegation unused since 08-16): remove the delegation rule + `.claude/agents/*.md`, keep CLI, run ~2,000 Fable requests, compare flags/1k against 1/500. If unchanged, next arm is the unkillable-wedge rule/2d wording (host-wedge/unkillable/panic vocabulary) or CLI rollback to 2.1.233. Pending user decision.
