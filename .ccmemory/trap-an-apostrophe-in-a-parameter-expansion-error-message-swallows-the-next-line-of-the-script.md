---
name: trap-an-apostrophe-in-a-parameter-expansion-error-message-swallows-the-next-line-of-the-script
description: TRAP (s132): ${1:?the running queue's log} opens a quote that runs into line 2, so the NEXT assignment vanished and the script died on an unbound var…
metadata:
  type: feedback
tags: [shell, harness]
---

# `${var:?message}` is subject to quote removal — never put an apostrophe in it

```bash
set -u
AFTER_LOG=${1:?the running queue's log, tests/evidence/lapq_<label>.log}
AFTER_BOUND=${2:?the sum of that queue's own lap bounds, in seconds}
...
case $AFTER_BOUND in            # line 38: AFTER_BOUND: unbound variable
```

The word after `:?` goes through quote removal like any other word. The `'` in
`queue's` on line 2 OPENS a single quote; it stays open until the `'` in
`queue's` on line 3 closes it — so line 3's text was consumed as part of line
2's expansion and `AFTER_BOUND` was never assigned at all.

## Why it is nasty

- `bash -n` PASSES. The quotes balance eventually (there are other `'` further
  down), so the file parses; it just parses into something else.
- The error names a variable the reader can SEE being assigned two lines above
  the failure, which sends the search in the wrong direction.
- It only fires when the script is invoked, so a script written and launched
  detached fails silently in a `.out` file nobody is watching.

## The rule

No apostrophe in any `${var:?...}`, `${var:-...}` or `${var:=...}` word.
Write "the log of the queue to wait for", not "the running queue's log".
Same for `#`, `}` and backticks. If the message needs punctuation, `[ -z "$1" ]
&& { echo "..." >&2; exit 2; }` takes an ordinary quoted string.

Verified by running the script with no arguments and with a bad argument before
backgrounding it — a detached launch whose only evidence is a `.out` file is
worth two seconds of foreground argument checking first.
