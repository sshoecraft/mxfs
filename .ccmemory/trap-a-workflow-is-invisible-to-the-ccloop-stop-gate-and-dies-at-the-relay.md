---
name: trap-a-workflow-is-invisible-to-the-ccloop-stop-gate-and-dies-at-the-relay
description: MEASURED: an in-flight Workflow registers ZERO with keepgoing's background gate (same class as rig work) and is SIGKILLed at a cutoff relay; only jou…
metadata:
  type: feedback
tags: [ccloop, workflow, stop-gate, relay, delegation]
---

# A Workflow is invisible to ccloop's Stop gate, and dies at the relay

Measured 2026-09-17 by a probe running *inside* a live Workflow, so the state it
observed was the answer.

## The gate cannot see it

`keepgoing._pending_background_task_count` globs
`/tmp/claude-<uid>/*/<session-id>/tasks/*.output` and counts only paths that are
the target of some `/proc/<pid>/fd/<n>` symlink. A detached sampler replicating
that logic exactly took 13 consecutive samples over a Bash-free window while a
Workflow subagent was demonstrably executing: **`LIVE_COUNT=0` on 13 of 13.**

- Workflow subagents share the PARENT session id (`CLAUDE_CODE_SESSION_ID`
  identical, `CLAUDE_CODE_CHILD_SESSION=1`), so the glob *finds* the directory —
  it just finds nothing live in it.
- The only thing that ever holds one of those `.output` files open is an
  in-flight **foreground Bash call**. Measured: during one, that call's own pids
  held its `.output` and the count was exactly 1.
- So a Workflow is in the same class as a 32-node `run.sh` or an `ssh`/`nohup`
  launch: **it counts zero toward the gate.** Ending a turn on it in criteria
  mode gets "HAVE YOU MET THE CRITERIA?" re-fed, pushing the session to act when
  it was correctly waiting.
- NOT measured: a genuine `run_in_background: true` Bash task. That one does hold
  its `.output` open and IS counted. Do not generalise this finding to it.

## Two premises in ccloop's own code are now false

- `keepgoing.py:344-347` states the harness never reaps a finished command's
  `.output`. Measured across four listings: **foreground `.output` files ARE
  reaped on completion.** Every one created during the probe vanished; only
  parent-session outputs persisted.
- Even if the count were non-zero, `keepgoing.py:505-531` returns 0 in an
  interactive run (`CCLOOP_INTERACTIVE`) rather than blocking. Only the headless
  branch sleeps and re-feeds.

## The relay kills it

`DISABLE_AUTO_COMPACT=1` is set in every ccloop session, so there is no
summarize-and-continue inside a run. At the cutoff the hook writes
`halt-<sid>`, and the interactive watcher SIGTERMs the tracked child **plus a
pre-snapshotted descendant list**, escalating to SIGKILL after a 5 s grace;
headless relies on `PR_SET_PDEATHSIG`. A Workflow in flight goes with it.
`resumeFromRunId` would replay finished agents from cache but is same-session
only, so the post-relay session cannot use it.

## What to do instead

- Size a workflow to the **token headroom left**, not to wall-clock time. One
  10-agent run took 23.6 min; fired near the cutoff it is thrown away entirely.
- **Have the agents write findings into the repo while they run.** The script's
  return value only exists for a session alive to receive it; the script itself
  has no filesystem access, but its agents have full tools.
- The durable record is `<transcript-dir>/journal.jsonl` — one result line per
  agent with its FULL return value. Read it with `tools/workflow_journal.py`.
  A notification carrying a 382 kB return truncated all but ~30 kB of it.

## Cost, which is the opposite of the intuition

Workflow agents **inherit the session model** unless `opts.model` overrides it,
so a 10-agent run put 134 tool uses on Opus — roughly 134 requests against a
request-metered pool, where steering the same work by hand would have been
20-30. A workflow buys parallelism, independent perspectives, and a parent
context that never sees the raw reading. It does **not** buy fewer requests.
Use `model`/`effort` overrides on the mechanical stages if that matters.
