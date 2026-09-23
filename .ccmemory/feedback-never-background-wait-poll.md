---
name: feedback-never-background-wait-poll
description: NEVER poll for background work (until-sleep / TaskOutput-block / watching tasks/*.output). Backgrounding itself is now FINE and preferred — the two failures behind the old ban are fixed in code.
metadata:
  type: feedback
---

## What still stands (user, sess10 — "you just sat there waiting for me to answer for hours")

**NEVER wait by polling.** This part of the sess10 correction is permanent:

- no `until ... ; do sleep N; done` waiter
- no `TaskOutput block=true`
- no watching `tasks/*.output` for a marker
- no backgrounding a batch of runs and polling for a TALLY

Reasons, current as of 2026-08-22:
- every poll costs a **full request** on the session's own model;
- `TaskOutput` on a local agent dumps its raw JSONL transcript into context
  (~15K tokens in one recorded case, sess169);
- polling for a completion notification that is already being delivered to you
  is pure waste.

## What is NO LONGER true — backgrounding itself is fine

The sess10 rule banned *backgrounding* as well as *polling*, for two concrete
reasons. **Both were fixed in ccloop, verified 2026-08-22:**

1. *"Every `run_in_background` task leaves a `*.output` file the harness may
   not reap → the Stop gate keeps firing forever."*
   Fixed. `keepgoing._pending_background_task_count` now counts only an
   `.output` file **held open by a live process** (procfs, with an mtime
   window as the non-procfs fallback). Its docstring names the old
   presence-counting behaviour as the bug it exists to fix.
2. *"background+poll yields control back to the loop, which then blocks waiting
   for the USER."*
   Fixed. When live background work exists that gate emits
   `decision: block` — "Wait. Background command still running." — which keeps
   the session alive and is deliberately **not** counted against
   `CCLOOP_MAX_CONTINUES`. Separately the harness re-invokes the session when a
   background Bash exits, and subagent completions arrive as notifications.

Verified on the live run: `/tmp/claude-<uid>/-src-mxfs/<session-id>/tasks`
resolves exactly as the gate globs it.

## DO INSTEAD

- Fire the `Agent` (or `run_in_background` Bash), then **carry on with anything
  that does not depend on the result**. You do not have to be idle to receive
  the notification.
- While it runs, **find independent work** — read code, form the next
  hypothesis, write the diagnostic you will need when the result lands. This is
  almost always the right move and depends on no gate.
- **Ending the turn to wait is a narrow exception, and RIG WORK DOES NOT
  QUALIFY.** The Stop gate holds the session open only for a *locally live*
  task — a `run_in_background` Bash or `Agent` whose `tasks/<id>.output` is
  still held open by a running process on clyde. A 32-node `run.sh`, an
  `ssh`/`nohup` launch on the nodes, or anything the local submitter fired and
  returned from is **invisible to the gate**: `_pending_background_task_count`
  counts zero, keepgoing re-feeds "continue", and the session is kicked.
  Observed sess395: the session announced it was holding for a ~35 min rig
  series and was re-fed three times in a row. For rig work: keep working, or
  block in the foreground with a RULE 0 derived timeout.
- **Outside a ccloop run there is no gate at all.** Ending the turn there hands
  control back to the user — the original sess10 failure.
- Short work (under ~1 min) stays in the foreground. Backgrounding is for
  genuinely long or concurrent work, not the default.
- **Nothing required may be in flight at a relay boundary** — in-flight agents
  die with the session (sess169: an agent had read 21 memories but had not
  written the article). Check for pending tasks before signalling completion.
- A task exiting is not a task succeeding: read and validate its output.

## Why this changed

The old rule's remedy — "split runs longer than 10 min into per-iteration
foreground calls (~5 min each)" — manufactured long chains of consecutive
blocking Bash calls. As of ccenv v0.23.0 a `PreToolUse` hook refuses at 8
consecutive Bash calls, because 65% of this project's requests were mechanical
shell chains. The two rules collided head-on, and sessions were observed firing
a subagent and *then* writing `until [ -f tasks/<id>.output ]` waiters to poll
for it — paying requests to wait for a notification already in flight.

Supersedes the FOREGROUND half of [[feedback_wait_in_foreground]]; the
never-poll half stands.
