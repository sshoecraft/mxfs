---
name: trap-an-awareness-doc-over-256kb-is-refused-by-read-and-edit-whatever-the-offset-so-append-with-a-heredoc
description: TRAP (0.90.14): Read refuses dlm.md/xfs.md/pal.md (270-365 KB) even with offset+limit, so Edit cannot anchor; append sections with cat >> heredoc, fi…
metadata:
  type: feedback
---

# The three big awareness docs cannot be opened with the file tools

`.claude/awareness/subsystems/dlm.md` (~270 KB), `xfs.md` (~312 KB) and
`pal.md` (~365 KB) are over the Read tool's 256 KB ceiling, and the ceiling
is checked against the WHOLE file before `offset`/`limit` are applied:

    File content (311.6KB) exceeds maximum allowed size (256KB). Use offset
    and limit parameters ...

The message suggests offset/limit, but they do not help. Since Edit requires
a prior Read of the file, Edit cannot anchor into them either.

## What works

- Append a new section: `cat >> <doc> <<'EOF' ... EOF` (single-quoted
  heredoc so backticks and dollars survive).
- Fix one stale line: `sed -i 's/<exact old text>/<new>/' <doc>` and
  `grep -c` the new text afterwards to prove the edit landed.
- Locate a passage: `grep -n -B3 -A6 <symbol> <doc>`.
- `tests.md` (~1980 lines) and `tools.md` (~1640 lines) are still under the
  ceiling and take Read/Edit normally.

## Why it matters

The awareness protocol asks every session to fold what it changed into these
docs. A session that tries Read, gets refused, and moves on leaves the docs
stale for every later session. Budget one shell call for the append instead.
