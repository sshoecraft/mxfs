---
name: trap-editing-a-shell-script-while-bash-is-executing-it-shifts-the-interpreters-byte-offset
description: TRAP (s74): bash reads a script incrementally by byte offset; inserting lines into a RUNNING harness can resume it mid-token. Kill the run before edi…
metadata:
  type: feedback
tags: [harness, bash, rig, process]
---

# Never edit a shell script that is currently executing

`bash` does not slurp a script into memory. It reads it incrementally and keeps
a byte offset into the file. Inserting or deleting lines in a running script
shifts everything after the interpreter's current position, so it can resume in
the middle of a token and execute something that was never written.

This bit twice in one session:

1. Recognised in time: a wait bound needed fixing while a 15-minute lap was
   running. The lap was killed first, then edited.
2. Not recognised in time: a cleanup trap was added to
   `tests/fence_lost_response.sh` while a lap of that same script was still in
   its prep stage. The run had to be abandoned and restarted regardless of
   whether it had already been corrupted — because there is no way to tell from
   the outside which bytes the interpreter had consumed.

## The rule

Before editing a harness: stop the run (`TaskStop`, or kill the background
task), then edit, then re-run with a new label. A lap that was running during an
edit produces a result that cannot be trusted and must not be reported, even if
it appears to complete normally.

The same applies to a script being edited while a *subagent* or a background
`run_in_background` Bash call is executing it.
