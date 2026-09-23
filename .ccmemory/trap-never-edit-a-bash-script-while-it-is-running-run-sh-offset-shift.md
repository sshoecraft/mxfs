---
name: trap-never-edit-a-bash-script-while-it-is-running-run-sh-offset-shift
description: TRAP (sess445): editing run.sh while a board is executing it shifts byte offsets bash reads top-level code by — revert until DONE. Also: the .ccph ca…
metadata:
  type: feedback
---

# Never edit a bash script that a live process is executing

bash reads a script incrementally by file offset.  Function bodies already parsed are safe, but every top-level command after the current one is re-read from the saved offset — inserting or deleting bytes above that point makes the running instance execute mid-line garbage.  `run.sh` line ~1358 sits inside `run_coord()` but the board's top-level tail (the `.last_run.json` jq write, the `=== done` echo) follows it.

Rule: while any chain has `run.sh` (or any `tests/*.sh`) in flight, do NOT edit it.  Queue the edit for after the chain's DONE line.  If an edit already landed, revert it byte-identically (Edit with the exact inverse) before the running instance finishes its current compound command.

## The pending fix (sess445, re-apply after chain 34 DONE)
`run.sh:1358` kill-time phase capture: `pkill -f '$script'` matches the REMOTE shell's own `bash -c` command line (it carries the script path) and kills it before `dmesg | grep mxfs-CCph > /tmp/ccph_last` runs.  Proven on test1 after the 0.51.0 board: `/tmp/ccph_last: No such file or directory`, every `testN.ccph` artifact = one bare newline.  Fix: `pkill -f -- '[${script:0:1}]${script:1}'` (bracketed first char never matches its own pattern text).  Node-side `pkill -f` is fine (RULE 2c is host-only).
