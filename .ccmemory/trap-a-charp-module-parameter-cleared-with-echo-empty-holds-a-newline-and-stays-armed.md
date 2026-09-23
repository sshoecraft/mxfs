---
name: trap-a-charp-module-parameter-cleared-with-echo-empty-holds-a-newline-and-stays-armed
description: TRAP (s105): `echo '' > /sys/module/mxfs/parameters/<charp>` leaves the parameter holding "\n", not empty — a refusal injector cleared that way stays…
metadata:
  type: feedback
tags: [kernel, module-param, test-injector, measurement-integrity]
---

# A charp module parameter cannot be cleared with `echo ''`

## What happened

`tests/lu_reset_fence.sh` arms `lu_reset_krel_probe` (a `charp` module
parameter) for its refusal arm and then clears it with:

```sh
echo '' > /sys/module/mxfs/parameters/lu_reset_krel_probe
```

A sysfs store hands a `charp` parameter **the bytes that were written**, and
`echo ''` writes one byte: `"\n"`. So the knob was left holding `"\n"`, not
nothing.

The module's disarm test was `if (!p || !p[0]) return real;` — `"\n"[0]` is
`'\n'`, which is non-empty, so the injector stayed armed for the rest of the
lap with a substitute release of `"\n"`.

## What it cost

Every later fence on that node refused `kernel-unaudited` with an **empty**
release in the log, which reads exactly like an operator who cleared the knob
and a pin that refused for some other reason. The arm that had to issue a real
LOGICAL UNIT RESET never reached admission (`admit_run=0`), so the clause the
lap existed to measure went unmeasured, and the harness aborted on an empty
field rather than on a filesystem verdict.

## The rule

A knob that can be armed must be **disarmable**, and for a `charp` parameter
that means the reader trims surrounding whitespace and reads an all-whitespace
value as OFF. Do not fix it in the harness by writing some sentinel string —
the next caller will use `echo ''` too, because that is what clearing a sysfs
file looks like.

Applies to every `charp`/string module parameter in this tree, not just this
one. `int`/`bool` parameters are unaffected: `param_set_int` and friends parse
with `kstrtoint`, which skips the trailing newline itself.

## Corroborating shape

The same class of bug as
`trap-a-kernel-printed-hex-key-is-unpadded-and-compares-unequal-to-a-zero-padded-normalization`:
two strings that name the same thing compare unequal because one carries
formatting the other does not. Normalise at the one place that decides.
