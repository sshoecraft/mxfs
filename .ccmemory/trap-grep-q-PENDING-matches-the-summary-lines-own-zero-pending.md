---
name: trap-grep-q-PENDING-matches-the-summary-lines-own-zero-pending
description: TRAP (sess571): wait on a board by parsing a row count, never `grep -q PENDING` — a word test also matches summary/all-clear lines.
metadata:
  type: feedback
tags: [harness, substring, wait-loop]
---

# Wait on a board by a parsed number, never by `grep -q "PENDING"`

## What bit us (sess571, on the retired `showstat.sh`)

    timeout 420 bash -c 'while ./showstat.sh 2 tcp 2>&1 | grep -q "PENDING"; do
        sleep 20; done; echo BOARD_DONE'

`showstat.sh` ended every table with a totals line that always named every
status, `... 0 PENDING` included, so the word was present whether or not anything
was pending. The loop spun its whole 420 s and exited 124 on a board that had
finished minutes earlier — a `rc=124` that looks like a hung board.

`showstat.sh` no longer exists; the board is `tools/criteria.py`. Its
`Total:` line lists only the statuses present, so the literal "0 PENDING" is
gone — but a bare word test is still the wrong shape: the word also appears in
`criteria.py pending` output, in `measured` text, and in any future summary
wording. The lesson is the shape, not the tool.

## The family this belongs to

Identical in shape to `trap-bare-mount-rc-grep-matches-inside-umount-rc`: a token
that also appears inside the very line that reports its absence. Both turn "is X
still happening?" into "does the word X appear anywhere?".

## What to write instead

Match the **row's status column**, and count:

    tools/criteria.py 2 tcp --no-colour | grep -cE '^[0-9]+ +\| [^|]+\| PENDING '

**The general rule: when waiting on a condition, assert on a NUMBER you parsed,
never on the presence of a word that the "all clear" message may also contain.**

Waiting on a board at all is usually wrong here: `run.sh` in the foreground with
its own per-row budgets is the wait. See `feedback-sane-timeouts-derive-from-measured-wall-never-pad`.
