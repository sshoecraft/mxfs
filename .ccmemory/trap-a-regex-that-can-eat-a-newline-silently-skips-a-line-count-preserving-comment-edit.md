---
name: trap-a-regex-that-can-eat-a-newline-silently-skips-a-line-count-preserving-comment-edit
description: TRAP (0.89.90): strip_process_notes.py used \s* after a tag; a tag ending a line ate the newline, the line-count guard rejected the edit, and 616 tag…
metadata:
  type: feedback
tags: [tooling, regex, cleanup, verification]
---

A text transform that must preserve line counts (so compiled objects stay identical) usually has a guard that keeps the original when the count changes. If any pattern can match a newline, that guard turns a would-be edit into a silent no-op — the tool reports success and the target text survives.

What bit: scripts/strip_process_notes.py removed session tags with `SESS\s*:?[ \t]*`. Wherever a tag ended a comment line (`... sess438\n * identity carve`) the `\s*` took the newline, the comment's line count changed, and the whole comment was kept unedited. 0.89.89's CHANGELOG said the tags were removed; 616 remained.

How to apply:
- In any line-preserving rewrite, match horizontal whitespace only (`[ \t]*`), never `\s`.
- After such a tool runs, measure what is LEFT (count the target pattern across the tree), not only how many files it reports changing. A guard that falls back to "unchanged" hides its own misses.
- Also check the leftovers' kinds: here the remainder included dead pointers (names of stored notes that no longer exist) that the CHANGELOG had called intentional.
