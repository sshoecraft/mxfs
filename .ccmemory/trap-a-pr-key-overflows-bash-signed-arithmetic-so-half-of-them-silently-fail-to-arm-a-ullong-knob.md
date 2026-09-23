---
name: trap-a-pr-key-overflows-bash-signed-arithmetic-so-half-of-them-silently-fail-to-arm-a-ullong-knob
description: TRAP (s74g): $(( 0xf5413d536ca66aed )) is NEGATIVE in bash; a ullong module param rejects it and reads back 0. Half of all PR keys have the top bit s…
metadata:
  type: feedback
tags: [harness, scsipr, pr-key, bash, module-param]
---

# A PR key is a full unsigned 64-bit value and bash arithmetic is signed

MXFS PR keys are 64-bit and randomly distributed, so **about half of them have
the top bit set**. For those:

    $(( 0xf5413d536ca66aed ))   ->  -774270232416589075     (bash, signed)
    printf '0x%016x' "$(( … ))" ->  errors or wraps

Two things break, both silently and both only for half the keys:

1. **Arming a `ullong` module param.** `echo $(( VKEY )) > /sys/module/mxfs/parameters/dbg_prout_lose_key`
   writes a negative decimal; `param_set_ullong` rejects it and the knob stays
   **0**. The harness then runs a whole lap with the injection disarmed. Measured
   s74g: `got=ARMED=0x0000000000000000 want=ARMED=0xf5413d536ca66aed`.
2. **Comparing a key to itself.** `normkey() { printf '0x%016x' "$(( $1 ))"; }`
   cannot render it.

It is intermittent by construction: lap s74d's key was `0x08ef086a7fd6c4ea`
(top bit clear) and everything worked; the next lap drew `0xf541…` and failed.
The same shape as the zero-top-nibble padding trap — a key-dependent assertion
that passes repeatedly and then fails.

## Do this instead

    normkey() { python3 -c "import sys; print('0x%016x' % (int(sys.argv[1],16) & 0xFFFFFFFFFFFFFFFF))" "$1"; }
    keydec()  { python3 -c "import sys; print(int(sys.argv[1],16) & 0xFFFFFFFFFFFFFFFF)" "$1"; }

Write the decimal from `keydec` (or the `0x…` string — the kernel's
`kstrtoull(val, 0, …)` accepts a `0x` prefix), and compare the knob's readback
as **decimal against decimal**, since `param_get_ullong` prints `%llu`.

Never put a 64-bit key through `$(( ))`, and never assert on a bash-rendered hex
of one.
