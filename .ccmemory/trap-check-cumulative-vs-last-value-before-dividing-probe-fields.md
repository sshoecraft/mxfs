---
name: trap-check-cumulative-vs-last-value-before-dividing-probe-fields
description: TRAP (sess481): two wrong root causes in one session — naming a subtracted residue after an unmeasured mechanism, then dividing a last-value probe fi…
metadata:
  type: feedback
tags: [trap, method, instrumentation, sess481, rule4]
---

# TRAP (sess481): two ways to manufacture a confident wrong root cause from real data

Both happened in one session, on the same defect, and both survived long enough
to be written into the ledger before being caught.

## 1. A subtracted residue is not a measurement of what you suspect is in it

`P381-UNLK-CONTEND` reported `sleep_ms` and `wall_ms` for a contended CAW unlock.
Over 17,558 samples: mean wall 35.1 ms, mean sleep 9.3 ms. I subtracted, divided
the 25.8 ms by 2.7 attempts, got **9.42 ms**, called it "slot I/O service time",
and filed it as the root cause with a fix direction attached.

Nothing measured slot I/O. The residue contained *everything else in the loop* —
and two of those things (`find_slot`'s hash-chain walk, `caw_inode_backoff`'s
uncounted sleep) turned out to be un-instrumented entirely.

**Rule:** name a residue "unaccounted", never after the mechanism you suspect.
Then go find a direct probe for that mechanism. If none exists, that absence is
the finding.

## 2. Check CUMULATIVE vs LAST-VALUE before dividing one field by another

To refute (1) I used the direct probes — and got that wrong too:

```
P297-TKT read_ms 2374 / reads 10756 = 0.22 ms per read     # WRONG
```

`dlm/dlm_caw.c:6908` does `acq_read_ms = now - t0` — a plain **assignment** on
every poll, so `read_ms` is the **last** read's duration. `reads` is
**cumulative**. Dividing one by the other across samples is meaningless. Same
trap in `slept_ms`, which prints `last_sleep_ms` (`:6970`) while a genuine
cumulative `sleep_tot_ms` already existed a few lines away and simply was not
printed.

Read as the per-read values they actually are: **0.77 ms mean** (p50 1, p90 2,
max 32), and `P138-AGWAIT caw_svc_ms` **1.54 ms mean**. The conclusion survived —
a slot op is well under 2 ms against a 9.42 ms residue — but a conclusion
surviving a bad derivation is luck, not method.

The same error also produced a claim I had to **retract**: "~242 ms per acquire
wait unaccounted" came from comparing `el_ms` (cumulative) against `slept_ms` and
`read_ms` (both last-value). The acquire side is **unknown**, not anomalous.

## What actually held, and why

The unlock-side residue stands *because its two terms are both totals*:
`p381_sleep_ms` accumulates (`+=` at `:10675`, `:11148`) and `wall_ms` comes from
one `p381_t0` (`:10559`). Totals against totals.

## The check, before any division

1. Is each field cumulative or per-iteration? Grep its assignment: `+=` vs `=`.
2. Is the denominator counting the same episodes as the numerator?
3. Does a direct probe for the suspected mechanism exist at all? (Often one does
   and is already shipping — `P381-UNLK-CONTEND` had been in the build for a
   hundred sessions.)
4. If the answer is a residue, print it as a residue.

`tools/caw_unlock_audit.py` encodes all of this: it prints `UNACCOUNTED` in
capitals, refuses to call it slot I/O, and carries the caveat in its own output.
