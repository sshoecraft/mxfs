---
name: trap-editing-a-shell-script-while-an-instance-of-it-is-running-can-make-that-instance-resume-mid-file
description: TRAP (s132): adding lines to tests/lap_queue.sh while it was driving a 10-lap 3-hour queue shifts every later byte offset; bash re-reads by offset.
metadata:
  type: feedback
tags: [harness, shell, rig, safety]
---

# Never add or remove lines in a shell script that is currently executing

Bash does not slurp a script. It parses one complete command, executes it, and
comes back to the file at a saved BYTE OFFSET for the next one. Insert lines
above that offset while the script is running and the offset now points at a
different place in the text: the running instance resumes mid-command and runs
a fragment.

## What happened

`tests/lap_queue.sh` was driving the s130 queue — 10 laps, ~2.9 h, already one
lap PASSed. I added a `--after` chaining option near the top of the file
(+~1.4 KB before the main loop). The running instance was inside
`for entry in "${LAPS[@]}"` at the time, so nothing had gone wrong YET — bash
had the whole loop parsed in memory and would only return to the file for the
final `echo "QUEUE DONE ..."`. That line is what a chained queue waits for, so
the damage would have shown up three hours later as a queue that never reported
finishing and a successor queue that never started.

Reverted byte-exactly (the same text removed again, back to 4604 bytes) before
the loop ended, so nothing was lost.

## The rule this leaves

- A script the rig is running is READ-ONLY until it stops. Check what is
  running before editing anything under `tests/`.
- When the change is needed NOW, put it in a NEW file. That is not a versioned
  sibling and it is not editing around the problem: a new file physically
  cannot move a running one's offsets. `tests/lap_queue_chain.sh` exists for
  exactly this reason and says so in its header.
- A same-size edit is not a safe workaround either — the text at the offset
  changes even when the offset does not.
