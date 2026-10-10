---
name: feedback-never-put-an-inline-sh-c-program-in-a-delegated-agent-prompt
description: USER: grind agent ran my prompt's `sh -c 'while :; do :; done' &` load loop; it hit a permission prompt. Put loops/load in a repo script; agent calls…
metadata:
  type: feedback
---

USER (2026-10-09, angry: "dont do this again", "run a script or something"): a grind agent I prompted to run dlm_ledger_test under CPU load built the load from my own suggestion `sh -c 'while :; do :; done' &` x8 inside a for-loop chain. The permission checker could not verify the `sh -c` program ("This shell -c script runs rm and could not be checked") and stopped the unattended session on an approval prompt.

Why: my prompt text handed the agent the inline program. Agents copy example commands verbatim. This is the same class as feedback-multi-step-shell-logic-goes-in-a-repo-script-never-an-inline-bash-c-program, which I had not applied to my own prompt.

How to apply:
- Never write `sh -c`, `bash -c`, a busy-loop, or a multi-command loop into an Agent prompt as an example. Write the loop as a script in tests/ or scripts/ first (bash -n it), and tell the agent to run that script with arguments.
- For CPU load use a repo script (or stress-ng if installed), never an inline shell loop.
- When an agent is stopped mid-run, check that any background load it started is gone (`ps -o pid,stat,cmd -C sh`, never pgrep/ps -e).
