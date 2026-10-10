---
name: compiled-shell-quoting-eats-text-silently-and-harness-lint-or-audit-residue-understates-the-class
description: Shell word-eating traps (apostrophe in ${v:?}, backticks in ledger values) plus static audit/lint rules: arm-without-disarm, count-only residue.
metadata:
  type: feedback
tags: [compiled, shell, harness, ledger, lint, trap]
---

Four notes sharing one theme: a guard reports success while text or scope has silently gone missing, so the check must target the property, not the surface signal.

## Shell eats text and still passes every check

- [[trap-an-apostrophe-in-a-parameter-expansion-error-message-swallows-the-next-line-of-the-script]]: the word after `:?` in `${var:?msg}` undergoes quote removal. An apostrophe in "queue's" opens a single quote that runs into the next line, so the next assignment (`AFTER_BOUND`) never happens and the script dies later on an "unbound variable" that is visibly assigned two lines above. `bash -n` passes because quotes balance further down. Fires only on invocation, so a detached launch fails silently in a `.out` file. Rule: no apostrophe (also `#`, `}`, backtick) in any `${v:?...}`, `${v:-...}`, `${v:=...}` word. Use `[ -z "$1" ] && { echo "..." >&2; exit 2; }` instead. Run the script foreground with no args and with a bad arg before backgrounding.
- [[trap-never-put-backticks-in-a-ledger-set-value-bash-eats-the-word-silently]]: backticks in a `ledger_set.py prepend "..."` value are command-substituted; `next` ran as a command (stderr `command not found`, easy to skim) and the word was stored as an empty string. `ledger_set.py` printed `ok:` and `ledger_validate.py` printed `ledger OK` because a date-schema validator cannot see a missing noun. Rule: no backticks (nor `$(...)`, `$VAR`, `!`) in values passed to shell-argument tools; use plain single quotes around field names inside backtick-free double quotes. Read back what was written. `scripts/ledger_repair_backtick_damage.py --scan` finds eaten-word signatures (handles list-valued fields), `--fix <ID> <before> <after>` repairs. A doubled-space heuristic was removed: pasted SCST/kernel traces made it cry wolf. Whole-ledger scan: 0 wounds across 264 records beyond the one created.

## Audit the whole class before trusting the cleanup or the closure

- [[technique-audit-every-script-in-a-serial-queue-for-arm-without-disarm-before-launching-it]]: before launching a serial queue, statically audit every script for: each write to `/sys/module/mxfs/parameters/...` (name, value), each disarming write, each `trap` and its signals, each `exit` with line number (count exits after an arm not covered by the trap), each backgrounded helper (pid recorded? killed?), and the header's derived bound. Pure grep, delegable. It found `tests/fence_crash_cuts.sh` had no trap and no disarm across eight knobs and six exits after an arm; hidden because the DESTROY arm reboots the victim, while the SILENT arm and the VACUOUS exits leave the node up with the knob armed and helpers (unbounded churner) still writing. Cleanup is only as good as the worst arm; the rebooting arm proves nothing about the others, and adding a second arm reopens the hole.
- [[trap-a-count-only-lint-residue-understates-the-fabricated-verdict-class-by-an-order-of-magnitude]]: `harness_lint.py` counted 72 `ck "$(grep -c ...)"` verdicts over unguarded captures; the same defect applied to VALUES from remote substitutions (`$(rs ...)`, `$(cnt PAT)` running ssh) found 457 in 62 files. Driving the count class to zero would have read as closure. Rule: flag every filesystem-verdict input derived from remote execution unless acquisition and interpretation crossed a parent-observed boundary; never distinguish counts from values, never let the expected value decide scope. Boundary in `tests/lib/rig.sh`: `window_count_into`, `value_now_into` (exactly one result line or ABORT), `prep_require`, `MXFS_FAULT_RSX_NTH`; `scripts/harness_cnt_rewrite.py` migrates `cnt`-style helpers. Keep the redundant `capture_require` after `for n in $A $B` loops. A harness not runnable on this rig is "converted by reading, laps pending", an open obligation and not a disposition.

## Common lesson

Success output from the writer, the validator, `bash -n`, or a zero residue count is evidence about form only. Verify by reading back the stored value, running the script's argument-error path foreground, or widening the lint to the whole defect class.
