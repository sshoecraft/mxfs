---
name: trap-never-put-backticks-in-a-ledger-set-value-bash-eats-the-word-silently
description: TRAP (sess566): backticks inside a `ledger_set.py prepend "..."` value are command-substituted by bash — the word is replaced by nothing, the tool re…
metadata:
  type: feedback
tags: [trap, ledger, shell, sess566, tooling]
---

# Never put backticks in a ledger value

sess566. Writing a defect note ABOUT the ledger's own field names, I used markdown
backticks:

    python3 tools/ledger_set.py prepend <ID> next_step "... this record ALSO carries a
    populated `next`. defects.sh returned only the first populated field of ..."

Bash command-substituted it before `ledger_set.py` ever saw the argument. `next` ran as a
command, stderr showed `/bin/bash: line 1: next: command not found` — twice, easy to skim
past among tool output — and the word was stored as an EMPTY STRING. The sentence became
"this record ALSO carries a populated . defects.sh returned...".

**Every guard passed.** `ledger_set.py` printed `ok: prepend ... -> OPEN_DEFECTS.json`.
`ledger_validate.py` printed `ledger OK: 264 records, all dates present and well-formed` —
a date-schema validator cannot see a missing noun. The record simply lost the two words the
sentence was about, permanently, and nothing would ever have said so.

## The rule

- **No backticks in any value passed to a shell-argument tool.** Use plain single quotes
  for field names in ledger prose: `'next'`, not the markdown form.
- The same applies to `$(...)`, `$VAR` and `!` inside double quotes. Single-quoting the
  whole value is the safe default, but then the value cannot itself contain a single quote
  — which ledger prose usually does. Backtick-free double quotes is the workable rule.
- **Read back what you wrote.** `ok:` from the writer plus `OK` from the validator proves
  the file is well-formed, not that it says what you meant. One `--scan` or a `repr()` of
  the first 500 characters costs nothing.

## The scanner

`scripts/ledger_repair_backtick_damage.py`:

- `--scan` reports structural signatures of an eaten word (empty first element in a quoted
  list, a dangling article or a stranded full stop) across `next`/`next_step`/`summary`/
  `mechanism`/`evidence`, handling the records that store those as LISTS rather than
  strings — the first version died on the first such record and reported nothing about
  the rest.
- `--fix <ID> <before> <after>` replaces one exact substring.

A "doubled space" heuristic was tried and removed: this ledger is full of verbatim SCST
and kernel log excerpts whose own alignment uses runs of spaces, so it flagged two pasted
traces and nothing real. A scanner that cries wolf on pasted evidence gets ignored on the
day it is right.

Whole-ledger scan after the repair: 0 wounds across 264 records. The one I created was the
only one.
