---
name: trap-grep-q-PENDING-matches-the-summary-lines-own-zero-pending
description: TRAP (sess571): waiting on `showstat | grep -q PENDING` never exits — the summary line says "0 PENDING", so the word is always present.
metadata:
  type: feedback
tags: [harness, substring, wait-loop]
---

# `grep -q "PENDING"` never goes false — the summary line always says it

## What I wrote

    timeout 420 bash -c 'while ./showstat.sh 2 tcp 2>&1 | grep -q "PENDING"; do
        sleep 20; done; echo BOARD_DONE'

## Why it can never succeed

`showstat.sh` ends every table with a totals line:

    Total: 28 — 23 PASS, 3 FLAKY, 0 FAIL, ... 0 PENDING

The word `PENDING` is present **whether or not anything is pending**. The loop
spun for its whole 420 s budget and exited 124 on a board that had finished
minutes earlier. It cost 7 minutes of a rig window and produced a `rc=124` that
looks like a hung board.

## The family this belongs to

Identical in shape to the already-recorded
`trap-bare-mount-rc-grep-matches-inside-umount-rc`: a token that also appears
inside the very line that reports its absence. Both turn "is X still happening?"
into "does the word X appear anywhere?".

## What to write instead

Match the **row**, not the word — anchor on the per-row status column:

    ./showstat.sh 2 tcp | grep -qE '⏳ PENDING'          # still a word match, but row-scoped
    ./showstat.sh 2 tcp | grep -cE '^[0-9]+ +\|.*PENDING'  # count ROWS, not lines

or better, parse the totals line and compare the number:

    n=$(./showstat.sh 2 tcp | sed -n 's/.*, \([0-9]*\) PENDING.*/\1/p')
    [ "${n:-1}" = 0 ] && done

**The general rule: when waiting on a condition, assert on a NUMBER you parsed,
never on the presence of a word that the "all clear" message also contains.**

## Related, same session

`run.sh`'s own transcript labels the `open_defects` row `FAIL`, while
`showstat.sh` renders that same row `📋 POLICY`. Two renderings of one result —
so a scraper keyed on "FAIL" in run.sh output counts a policy row as a test
failure. Count from `showstat`, or exclude the policy row explicitly.
