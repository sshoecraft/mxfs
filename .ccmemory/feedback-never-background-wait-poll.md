---
name: feedback-never-background-wait-poll
description: NEVER use run_in_background + blocking waits / until-sleep-loops / TaskOutput-block / polling — they leave the session idle waiting on the user for H…
metadata:
  type: feedback
---

## HARD RULE (user, sess10, FURIOUS — "you just sat there waiting for me to answer for hours")

NEVER do any of these — they make the session HANG idle waiting on the user:
- `run_in_background: true` on Bash for long test runs, then `TaskOutput block=true` / a `until ... ; do sleep N; done` waiter / any polling loop to wait for it. This is the exact pattern that wasted HOURS this session.
- Spawning `until`/`while sleep` wait-loops (they ORPHAN and keep spinning → the ccloop Stop hook (`keepgoing.py` counts `*.output` files in the session tasks dir) then fires "Background command still running" FOREVER, forcing the user to keep answering).
- Backgrounding a batch of test runs and polling for a TALLY/marker.

## DO INSTEAD (this is also [[feedback_wait_in_foreground]]):
- Run long things in the FOREGROUND and let the turn BLOCK on them. Foreground Bash caps at 10 min.
- If a run is longer than 10 min, SPLIT into per-iteration foreground calls (~5 min each), one Bash call per chunk. Do NOT background the whole batch.
- A single `./run.sh 2 tcp` full suite (~6 min) fits in one foreground call. Run it foreground.
- Every `run_in_background` task leaves a `*.output` file that the harness may not reap → the Stop gate keeps firing. Avoid creating them.

**Why:** background+poll yields control back to the loop, which then blocks waiting for the USER — the user is NOT supposed to be in the loop (autonomous ccloop), so the whole thing stalls for hours. Foreground keeps the turn active and self-completing.

**How to apply:** default to foreground Bash for EVERYTHING, including multi-minute test suites and reproducers. Only ever background a command if it is truly fire-and-forget AND you will never wait on it. When in doubt: foreground.
