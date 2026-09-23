---
name: trap-a-count-only-lint-residue-understates-the-fabricated-verdict-class-by-an-order-of-magnitude
description: TRAP (D-A-TEST-HARNESS, sess56): the lint counted 72 grep -c verdicts over unguarded captures; the same rule applied to VALUES fed straight from $(rs…
metadata:
  type: feedback
---

# A count-only residue understates the class

**What bit.** The migration control for D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS was `scripts/harness_lint.py`'s count of `ck "$(grep -c X file)"` assertions over captures no `capture_require` guarded. It read 72 in 36 files when the design consult (2026-09-18, Astra) pointed out that a verdict fed by a VALUE from a remote substitution — `ck "size" "$(rs 20 B "stat -c %s f")" 0`, `x=$(rs …); ck … "$x"`, `$(cnt PAT)` where cnt runs ssh — is the same defect: a fabricated FAIL is still a verdict about MXFS taken from no measurement, and a producer can print the expected scalar and then fail (`echo 0; exit 1`) so even "fails closed" can PASS. Adding that class to the lint found **457** in 62 files. Driving the count class to zero (done, sess56) would have read as closure while the larger class stood untouched.

**The rule.** Flag every filesystem-verdict input derived from remote execution unless its acquisition and interpretation crossed a parent-observed boundary. Do not distinguish counts from values, and never let the expected value decide scope.

**What the boundary looks like now** (`tests/lib/rig.sh`, 0.87.18): `window_count_into var node t mark pattern tag` (acquires the marked ring into its own file, requires the run-to-end sentinel AND the mark, counts locally, assigns with `printf -v` in the parent); `value_now_into var node t file line-regex what cmd` (exactly one result line or ABORT; a value-then-fail is caught by the status record); `prep_require file what` (NODE_PREP_FAIL, or no record, is an ABORT even when a later command in the list succeeded); `MXFS_FAULT_RSX_NTH=<n>` (the n-th measurement of any adopted harness goes to an unresolvable host: a library-level fault lap with no per-harness code, proven by the STAGE FAULT line). `scripts/harness_cnt_rewrite.py` moves `cnt`-style helpers across mechanically (shapes pat / node-pat / node-mark-pat / fixed / value).

**Also ruled:** keep the redundant explicit `capture_require` after a `for n in $A $B` loop even though the lint now learns bounded loop variables; a harness that cannot run on this rig is "converted by reading, laps pending" — an open obligation, not a disposition; the device inventory (wrong-but-valid instrument) is a separate identity record, while error-text-as-absence stays in this one.
