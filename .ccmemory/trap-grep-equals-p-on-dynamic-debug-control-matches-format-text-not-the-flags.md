---
name: trap-grep-equals-p-on-dynamic-debug-control-matches-format-text-not-the-flags
description: TRAP (0.90.55): `grep '=p' /proc/dynamic_debug/control` counted 7 "enabled" mxfs sites; all were =_ — the match was format text (at=put_super, site=p…
metadata:
  type: feedback
tags: [measurement, dyndbg]
---

Counting enabled dynamic-debug sites with `grep " \[mxfs\]" /proc/dynamic_debug/control | grep -c "=p"` reported 7 on both PVE hosts (and on the July build's evidence). Every one of them was `=_` (no flags): the `=p` substring was inside the FORMAT STRING — `at=put_super`, `site=pr_demote`, `via=pubob`. A defect record briefly carried "7 sites enabled" as evidence of why the log flooded.

**Why:** the control line is `file:line [module]func =FLAGS "format"`; a substring match over the whole line hits the format.

**How to apply:** match the flags field only, e.g. `awk '$3 ~ /^=p/'` (field 3 is `=flags` after `file:line` and `[module]func`), or `grep -E '\] *[^ ]+ =p[a-z]* "'`. Same family as the substring-contamination traps: anchor every count to the field it means.
