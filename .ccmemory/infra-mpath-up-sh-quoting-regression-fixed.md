---
name: infra-mpath-up-sh-quoting-regression-fixed
description: scripts/mpath_up.sh had a post-sess6 quoting regression (raw apostrophe + raw single-quoted sed inside the single-quoted NODE_ENSURE block) → syntax…
metadata:
  type: project
---

## scripts/mpath_up.sh quoting regression — FIXED (2026-07-06, ccloop 5bea4199)

### Symptom
`scripts/mpath_up.sh status|up N` → `line 117: syntax error near unexpected token '('`.
Script was completely unusable, so nothing could (re)assemble /dev/mapper/mpatha on nodes
that lost their iSCSI sessions. This is why 16/caw formation failed: test9–16 had iscsid
active but **0 iSCSI sessions → no mpatha → mxfs mount "Can't lookup blockdev" → converge FAIL**.
(test1–8 were unaffected because they already had healthy mpatha from prior sessions.)

### Root cause
`NODE_ENSURE='...'` (lines 73–134) is a single-quoted command block; literal inner single
quotes MUST use the `'"'"'` idiom (see line 80 `victim'"'"'s`). A post-sess6 edit that added
the "node.startup=automatic in iscsid.conf" feature introduced TWO raw-single-quote bugs:
- line 117 comment `iscsid.conf's default` — unescaped apostrophe closed the string early,
  making the following `(manual ...)` parse as code → `(` syntax error.
- line 119 `sed -i 's/^node.startup = manual/.../'` — raw single quotes inside the block.

### Fix (log/quoting only)
- line 117: removed the apostrophe (`iscsid.conf's` → `iscsid.conf`).
- line 119: sed switched to double quotes (`sed -i "s/.../"`), which pass through the
  single-quoted block literally and run identically on the node.
`bash -n scripts/mpath_up.sh` → SYNTAX OK. NODE_ENSURE block now single-quote-balanced.

### Lesson for the ladder
Before EVERY `./run.sh N caw` at a node count whose upper nodes may have lost sessions, run
`scripts/mpath_up.sh up N` first — run.sh does NOT assemble mpatha, it assumes it exists.
This g
gates 16 and 32. See [[caw-multipath-ladder-progress-sess-5bea4199]].
