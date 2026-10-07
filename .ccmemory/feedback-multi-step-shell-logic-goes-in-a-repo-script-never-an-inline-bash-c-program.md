---
name: feedback-multi-step-shell-logic-goes-in-a-repo-script-never-an-inline-bash-c-program
description: USER 2026-10-06: a subagent's inline bash -c program (a function with $1/$2) stopped on "runs rm and could not be checked"; "write it to a script"
metadata:
  type: feedback
---

**What happened.** A grind subagent ran a whole program inline: `bash -c` with a shell function (`run() { local name="$1" cmd="$2" ...; bash -c "$cmd" ... }`) that it then called with command strings. Claude Code's safety checker cannot resolve what such a script executes, so it raised "This shell -c script runs rm and could not be checked — Do you want to proceed?" and the unattended run stopped on the user's screen.

**What the user said:** "dont do this again ... write it to a script or something".

**How to apply.**
- Any shell logic beyond a plain command or a short pipeline (functions, loops that build and eval command strings, `bash -c "$cmd"`, `run()` wrappers, `"$@"`) goes into a script file in the repo (`tests/`, `tools/` or `scripts/`), written with the Write tool and then run by path. Never an inline program in a Bash call.
- Every subagent prompt that delegates shell work must say this verbatim, because subagents do not see a correction made during the session: "Do not write shell functions or `bash -c` programs; run each command as its own plain Bash call, or write a script file under the repo's tests/ or tools/ and run that."
- Related trap, same checker: `trap-a-bash-c-chain-that-runs-a-function-with-dollar-at-is-refused-by-the-rm-safety-check`.
