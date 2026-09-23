---
name: trap-a-sweep-keyed-on-one-name-and-a-path-scan-that-eats-dot-directories
description: TRAP (memory triage, 2026-09-10): two silent misses in a 2,800-file sweep — filename vs frontmatter name disagreed on 27 files, and lstrip("./") ate…
metadata:
  type: feedback
tags: [sweep, tooling, evidence, paths]
---

Two ways a tree-wide sweep reported success while missing files. Both were
found only because a verification pass was run afterwards that did not trust the
sweep's own output.

## 1. The filename and the `name:` field disagree

A memory's frontmatter `name:` is what the index keys on; the filename is
whatever it was written as. In this store 27 of 2,801 files disagreed —
`v3-version-history.md` held `name: v0.2.X-v0.3.X version history`,
`v5-history.md` held `MXFS v5 Project History`, `tcp_dlm_straggler.md` held
`TCP DLM straggler issue`.

Consequence: a plan keyed on filenames silently did not classify those rows, and
a delete keyed on `name` did not remove those files. Three documents that were
meant to move to `docs/` were never moved, and nothing errored — the content
survived only because the orphan files stayed on disk.

**Reconcile both directions before acting**: rows with no file, and files with no
row. `ls` and the index must agree, and neither one alone is the inventory.

## 2. `lstrip("./")` eats the dot of a dot-directory

`grep -rFo -f names .` prints `./.claude/awareness/build-history.md`. Stripping
the prefix with `path.lstrip("./")` strips *any* leading `.` or `/` character —
the result is `claude/awareness/build-history.md`, which does not exist. The
rewrite pass then hit `if not os.path.exists(path): continue` and skipped every
dot-directory in the tree.

116 citations across 7 awareness docs were left pointing at removed files, and
**the run printed no error and no warning** — it reported the files it did
rewrite and said nothing about the ones it could not find. Use
`path[2:] if path.startswith("./")`, and make a skipped path print itself rather
than `continue` in silence.

## The general shape

Both misses share it: the sweep's own output was consistent with success. What
caught them was a separate check asking the opposite question — "is any pointer
in the tree now dangling?" and "does any file lack an index row?" A sweep that
cannot fail loudly needs an independent verifier, and the verifier must not
reuse the sweep's own path handling.

One more thing that check surfaced: collapsing `.md.md` to `.md` is not
idempotent, because `.md.md.md` collapses to `.md.md`. Replace the whole run
(`(?:\.md){2,}`) in one substitution, or loop until the count reaches zero.
