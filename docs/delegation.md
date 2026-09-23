# Delegation — why Fable is not using agents, what it costs, and how to fix it

**Written 2026-08-22 (sess390) on the user's directive: "look at the entire
looping and development environment and determine how we can get Fable to use
agents and not burn so many tokens."**  Companion to `docs/cost-audit.md`
(the quota is ~4,430 **Fable requests**/week; every request costs the same
regardless of size) and to CLAUDE.md the delegation rule.  Measurement script:
`scripts/ccloop_delegation_audit.py`.

This document is the analysis and the proposal.  Nothing in it has been
applied to CLAUDE.md, hooks, or the agent roster; those are the user's
decisions and are listed in §5 as discrete items.

---

## 1. What the Fable requests are actually spent on

`scripts/ccloop_delegation_audit.py --files 208095bf f527479f 241f6dcb 816f7198 75a34d51`
(the five Fable loop sessions 08-21 20:23Z → 08-22 12:09Z, 721 requests):

| category | share of requests | delegable? |
|---|---:|---|
| Bash text/listing (grep, sed -n, cat, wc, ls, find, awk as the command) | 23.6% | yes |
| Bash fleet-ssh (`tools/mxfs_sshpass.sh` / virsh sweeps) | 20.6% | yes |
| **Read** (source, the Read-tool rule injection) | 15.0% | no |
| Bash harness-run (`run.sh`, showstat, tests/*.sh, bench/) | 12.1% | yes |
| **Edit** | 12.1% | no |
| Bash build-deploy (make, scp mxfs.ko, insmod/rmmod/modinfo) | 5.0% | yes |
| Bash dmesg/journalctl on the host | 2.5% | yes |
| Bash ledger (`defects.sh`) | 2.3% | yes |
| ccmemory write/get/list/search | 3.4% | no |
| Bash transcript parsing (`python3 … *.jsonl`) | 1.0% | yes |
| GPT consults | 1.0% | no |
| everything else | 1.4% | — |

- **65% of requests were purely mechanical** — every tool call in the request
  was a delegable kind.
- **50% of all requests (364 of 721) sit inside chains of ≥3 consecutive
  mechanical requests.**  That is the number that matters (see §2): each such
  chain is one `Agent` call's worth of work.
- **`Agent` calls made: 0.**  In the 08-15 Fable sessions (run sessions
  330-380, 1,337 requests) the same numbers were 42% mechanical, 22% in
  chains, 0 Agent calls.  Since the delegation rule landed (08-15) the `Agent` tool has
  been called 5 times in this project, all from the Opus-5 session that
  wrote the rule.

The same audit run on the session writing this document (before it started
delegating) read 70% mechanical / 47% in chains — 18 requests of transcript
parsing alone.  The pattern is not a property of a few sessions.

## 2. The arithmetic — when delegation saves a request and when it does not

An `Agent` call is one Fable request.  The turn that consumes its result is a
turn the session would have had anyway.  Therefore:

- **Delegating a single Bash call saves nothing.**  A 32-node poll that the request-batching rule
  already batches into one `for … & done; wait` costs one request either way.
- **Savings = (requests the chain would have taken in the parent) − 1.**  A
  chain of 5 mechanical requests — run the lap, read the board, grep dmesg on
  the failing nodes, pull the counters, tabulate — is 5 Fable requests in the
  parent and 1 Fable + ~5 sonnet requests when delegated.
- So the target is **chains**, not calls.  The audit's "saveable" column is
  Σ(chain length − 1) over chains of ≥3.  For 08-21/22 that is 364 of 721
  requests — the loop could have run the same day on roughly half the Fable
  pool, with the other half billed to sonnet.

Verified today from a **Fable** parent (sess390, `rig-runner`, 4-node
mount/srcversion poll): the subagent transcript shows `claude-sonnet-5`, 2
requestIds, 1 tool call, 11.5 s wall; the parent spent 1 Fable request on the
`Agent` call.  Model attribution from a Fable parent was the cost audit's
load-bearing unverified item (§10 item 1); it now holds.  Pool *debit* is
still only provable at the next exhaustion: if subagent requests count
against the Fable pool, the Fable-model request count at exhaustion will land
below the 4,430 ± 4% constant by about the subagent total.  Check it with
`scripts/ccloop_request_audit.py` then.

## 3. Why sessions do not delegate — root causes, each with the evidence

1. **the delegation rule is written as optional guidance and argues against itself.**
   "Delegate multi-turn, low-return work" is a suggestion, not a trigger; the
   rule then spends two-thirds of its length on hazards — "the cap is itself a
   hazard", "delegation saves requests, not context", "netted roughly
   break-even".  A session reading it has been given permission not to.  It
   sits at line 435 of 700, below the request-batching rule, whose "batch side-effect-free calls"
   reads as the complete answer to the request question.
2. **A direct conflict with the foreground rule.**  Development Notes: "WAIT
   IN THE FOREGROUND, not the background … Do NOT spawn it with
   `run_in_background: true` + a Monitor to poll"; feedback memory
   `feedback-never-background-wait-poll`.  The `Agent` tool *is* background
   work by construction ("Subagents run in the background; you'll be notified
   when one completes").  Nothing in the tree says the Agent notification is
   the sanctioned exception, so the foreground rule wins.
3. **the Read-tool rule + "never delegate reading" pull locate-and-read into the parent.**
   the Read-tool rule says read source with `Read` for the ccmemory injection; the delegation rule
   says never delegate reading the 2-3 files that matter.  Both are right, but
   neither says the *locating* — the grep/ls/wc/find sweeps that are 24% of
   requests — belongs to a subagent, and the session does locate+read as one
   activity.
4. **The roster is two agents with narrow triggers.**  `rig-runner` ("multi-
   node ssh sweep") and `log-sweeper` ("find every occurrence of X").  There is
   no agent for the chain shapes that actually recur: run a board lap and
   triage the failures; build+deploy+verify across the fleet; mine the
   transcripts; query the ledger; orient at session start.  `log-sweeper` is
   pinned to `model: opus`; the user wants sonnet for filesystem work.
5. **The loop never mentions agents.**  The ccloop session prompt
   (`.ccloop/runs/…/session-N.prompt`, 16 KB) and `.ccloop/state.sh` contain
   no occurrence of "agent", "delegate", "sonnet".  The orientation ramp
   (memory_list, ledger, rig poll, tree diff — ~5 requests/session) is done
   by hand every session.
6. **Nothing measures it, so nothing feeds back.**  `ccloop_behavior_audit.py`
   tracks Read-vs-Bash and the orientation ramp; request/token audits track
   totals.  No number says "this session spent 65% of its requests on
   mechanical chains and delegated none"; the session never sees its own burn.
7. **Nothing enforces it.**  Every behavioural change in this project that
   actually stuck was mechanical: the permission-prompt rule allowlist, `clyde_preflight.sh`
   as a gate inside `run.sh`, the kmsg guard, the ccmemory PreToolUse hook
   that moved the Read share from 8% to 42%.  the delegation rule has prose only.

## 4. Design principles for the fix

- **Enforce at the chain shape, not the call.**  The hook must not forbid a
  single grep; it must make the *second and third* mechanical request in a
  row expensive to keep doing by hand — or simply refuse the shapes that are
  always chains (fleet loops, `run.sh`, build+deploy, transcript parsing).
- **Subagents return raw evidence with commands and pre-truncation totals**
  (the delegation rule's cap hazard stands; it belongs in the agent definitions, not as a
  reason for the parent to do the work itself).
- **Sonnet by default** for filesystem/rig/log work; haiku only for trivially
  bounded queries (ledger lookups); opus never needed for mechanical work.
- **The parent keeps**: `Read` of the files it must understand (the Read-tool rule),
  `Edit`/`Write`, fix design, ledger dispositions, GPT consults, ccmemory.
- **Measure before and after with the same script**, denominated in requests.

## 5. Proposal — discrete items, each needs the user's yes

### 5.0 Where it lives: ccloop (`/src/ccenv/ccloop`), not only this project

Sessions are continued by ccloop.  It already owns the three places the
fix has to touch — the prompt (`runner._build_prompt`: preamble + prior
transcript pointer + resume digest + `state.sh` block), the hooks
(`install.HOOKS`: `PostToolUse→guard`, `Stop→keepgoing`, self-registered
in `~/.claude/settings.json`), and the between-session digest
(`summarize.py`).  Building delegation there makes it project-agnostic
plumbing, the way the state hook is: a project opts in by supplying files,
no files = byte-identical behaviour.  Proposed ccloop 0.14.0 / ccenv 0.23.0:

| piece | where | what |
|---|---|---|
| `ccloop delegate` | new `delegate.py`; `HOOKS["PreToolUse"]="delegate"` | PreToolUse hook, gated on `CCLOOP_RUN_ID`.  **Passes through when the hook input carries `agent_type`** — the CLI's base hook payload is `{session_id, transcript_path, cwd, prompt_id, permission_mode, agent_id, agent_type, effort}` (read from the 2.1.239 binary), so subagent tool calls are distinguishable without any marker file.  Reads `<project>/.ccloop/delegate.rules` (`agent<TAB>regex<TAB>message`, one per line; absent = no-op).  On a match against `tool_input.command` it emits `permissionDecision: deny` with a reason naming the agent, and appends `delegate-deny` to `hook-events.log`. |
| `## Delegation` prompt section | `runner._build_prompt` | When `<project>/.claude/agents/*.md` exist: roster from their frontmatter (name, model, description) + the standing instruction — delegate chains not calls; an `Agent` call is the sanctioned background wait; the hook refuses the listed shapes — + the rules file's triggers. |
| delegation line in the resume digest | `summarize.py` + `transcript.py` helpers | Previous session: requests, Bash-only consecutive request chains ≥3, `Agent` calls, subagent requests by model (`<session>/subagents/agent-*.jsonl`).  The session sees its own burn every time. |
| tests/docs | `tests/test_delegate.py`, README (Configuration + a "Delegation" section), DESIGN (`delegate.py`, hooks table), CHANGELOG | per ccenv convention |

Project side (this repo): `.ccloop/delegate.rules` with the shapes in §5.1,
the roster in §5.2, the delegation rule rewrite in §5.3 (CLAUDE.md then only has to
say *why*; ccloop says *what* and enforces it).

### 5.1 Enforcement hook (the lever that will actually change behaviour)

A project `PreToolUse` hook on `Bash` (`.claude/settings.json`) that **denies,
with a reason naming the agent**, parent-side commands whose shape is always a
chain:

| shape (regex on `tool_input.command`) | deny message |
|---|---|
| `mxfs_sshpass` inside `for`/`while` or with `&`…`wait` (fleet sweep) | "fleet sweep → Agent rig-runner" |
| `run.sh`, `showstat.sh`, `tests/*.sh`, `bench/*` | "harness run + triage → Agent board-triage" |
| `make modules`/`make clean`, `scp … mxfs.ko`, `insmod`/`rmmod` | "build/deploy/verify → Agent build-deploy" |
| `python3 … .jsonl` under `~/.claude/projects` | "transcript mining → Agent transcript-miner" |
| ≥3 `;`/`&&`/`|`-joined grep/sed/cat/wc/ls/find on tree paths | "tree sweep → Agent tree-scout" |

Open question to settle first (15 min): the `PreToolUse` input carries
`session_id, transcript_path, cwd, hook_event_name, tool_name, tool_input,
tool_use_id` — no `agent_type` (that field exists only on `SubagentStart`/
`SubagentStop`).  The hook must let the same shapes through when the caller
IS the subagent.  Test: a logging hook, one subagent Bash call, compare
`transcript_path` (expected `<session>/subagents/agent-*.jsonl`).  If it does
not differ, a `SubagentStart` hook can write `<run-dir>/subagent-active-<id>`
and the Bash hook allows while any exists (leaky during overlap, acceptable).
Escape hatch: none.  A model-readable override will be used.

### 5.2 Agent roster (all sonnet unless noted; each embeds the budget, unkillable-wedge and inspect rules verbatim, returns raw evidence, reports commands + pre-truncation totals, never widens a timeout)

| agent | model | does | replaces (share of requests) |
|---|---|---|---|
| `rig-runner` (exists) | sonnet | fleet polls, per-node commands, deploy verification | fleet-ssh 20.6% |
| `board-triage` (new) | sonnet | run a lap/board via `run.sh`, then for each FAIL collect per-node results, dmesg excerpts (capped), counters; structured evidence table | harness-run 12.1% + the dmesg/fleet chain after it |
| `build-deploy` (new) | sonnet | `make clean && make modules`, srcversion, fleet deploy, per-node `sv` verify, rc table | build-deploy 5.0% |
| `tree-scout` (new) | sonnet | grep/ls/wc/find/sed sweeps across the tree and logs; returns `file:line`, counts, capped excerpts | text/listing 23.6% (the multi-step part) |
| `log-sweeper` (exists) | **opus → sonnet** | as now | overlaps tree-scout; keep for dmesg-capture sweeps or merge |
| `transcript-miner` (new) | sonnet | the `~/.claude/projects/*.jsonl` parsing (requests, models, flags, gaps) | transcript 1% (but 16% of *this* session) |
| `ledger-reader` (new) | haiku | `./defects.sh` queries, one entry or the queue; never the whole file | ledger 2.3% |
| `orient` (new) | sonnet | session-start bundle: `memory_list` summary is NOT delegable (MCP), but rig state + tree diff + ledger queue + last-run board in one report | ~3 of the ~5 ramp requests/session |

### 5.3 the delegation rule rewrite (text to be reviewed before it lands)

- Move the hazards into the agent definitions; make the rule a trigger table:
  "the next step is X → `Agent` Y.  A parent Bash that does X is a delegation rule
  violation and the hook will refuse it."
- State the exception to the foreground rule explicitly: "An `Agent` call is
  the sanctioned background work.  Wait for its notification; do not poll."
- State the arithmetic: "delegate chains, not calls — a single batched Bash
  stays in the parent."
- Keep: never delegate `Read` of the files you must understand, edits, fix
  design, ledger dispositions; a disposition-critical negative is re-run in
  the parent.

### 5.4 Loop plumbing

- `.ccloop/state.sh`: add two derived lines to the session prompt — the agent
  roster with one-line triggers, and the previous session's delegation audit
  ("N requests, M% mechanical, K chains, 0 Agent calls") so the session sees
  its own burn.
- `docs/cost-audit.md` §1: add `scripts/ccloop_delegation_audit.py` to the
  re-audit command list; §10: the delegation rule pool-debit check at next exhaustion.

### 5.5 Measurement and the interaction with the safeguard flags

KPIs, all in requests: Fable requests/session; mechanical share; chains ≥3;
saveable; `Agent` calls; subagent requests by model; closures/week (the only
outcome metric, cost-audit §3.2).  And flags per 1,000 Fable requests: the
flagged turns (`docs/history/docs/history/fable-flag-rate-jumped-9x-0821-confounded-claude-md-vs-cli.md`)
all carried raw rig forensics in the Fable context; delegation moves that
text into sonnet's context, so the flag rate is expected to fall with
delegation rather than rise — measure it alongside.

### 5.6 Expected effect

If the 08-21/22 mix holds and chains are delegated: ~50% of Fable requests
move to sonnet.  At the 4,430/week cap that is roughly double the loop-hours
per credit week on the premium model, plus whatever the flag-rate change
yields.  Not a projection of closures — requests-per-closure has been flat
across every configuration tried (cost-audit §3.2.4); this buys more
requests of loop per week, and the closure count is the number to watch.

## 6. Open risks

- Subagent model unavailable → does the work silently run on the parent model
  at full price?  Unknown (cost-audit §10 item 1).  Detect with the audit
  (a subagent transcript whose model is the parent's).
- Sonnet/haiku pools may have their own caps; unknown.  Detect at exhaustion.
- Capped reports hide evidence (the delegation rule hazard).  Mitigation is in the agent
  definitions: exact commands + pre-truncation totals; parent re-runs any
  negative it intends to put in the ledger.
- Hook over-reach blocks a parent that genuinely must run a one-off fleet
  command.  Keep the deny set to the always-chain shapes; review the hook's
  deny log weekly.
