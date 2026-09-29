---
name: trap-grep-in-the-tool-shell-is-a-ugrep-function-and-its-v-q-exit-code-on-empty-input-is-zero
description: TRAP: in Claude Code's Bash tool (and subagents) grep is a ugrep-backed function; `grep -vq PAT` on EMPTY input exits 0 (GNU: 1). Test counts, not ex…
metadata:
  type: feedback
tags: [grep, ugrep, shell, harness, watcher, false-positive]
---

# `grep` in the tool shell is a function over ugrep

**What happened (0.90.24 gate chain):** a watcher agent's stop condition was

    grep -a '^LAP ' summary | grep -avq ' rc=0 '   # "some lap did not return 0"

The chain had just started, the summary held no LAP line yet, and the
condition was TRUE: the agent printed `STOP lap-failed` with `laps_done=0`
after 40 s and returned, leaving a 78-minute chain unwatched.

**Why:** in the Bash tool's shell, and in every subagent's, `type grep` prints
`grep is a function`; it execs a bundled `ugrep -G ...`.  Measured side by
side on empty stdin:

| command | tool-shell function | GNU grep 3.11 (`command grep`) |
|---|---|---|
| `printf '' \| grep -avq PAT; echo $?` | 0 | 1 |
| `printf '' \| grep -q PAT; echo $?` | 1 | 1 |
| `printf '' \| grep -avc PAT` | prints 0 | prints 0 |

Only the exit status of `-v -q` on empty input differs; counts agree.

**What to do:**
- In anything typed into the Bash tool or handed to an agent, decide on a
  COUNT (`n=$(... | grep -avc PAT); [ "$n" -gt 0 ]`), never on the exit
  status of `grep -v -q`.
- Or call `command grep` to get GNU grep.
- Scripts in the tree run as their own `#!/bin/bash` processes and do not
  inherit the function, so a condition that is right in a script can be wrong
  when the same line is pasted into the tool.  Test pasted conditions on empty
  input first.
- sed back-references stop at `\9`: `\11` is `\1` followed by `1`.  A report
  command with more than nine groups prints garbage that looks like data.
