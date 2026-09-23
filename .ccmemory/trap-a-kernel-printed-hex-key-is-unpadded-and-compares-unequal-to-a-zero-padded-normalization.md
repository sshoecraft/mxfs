---
name: trap-a-kernel-printed-hex-key-is-unpadded-and-compares-unequal-to-a-zero-padded-normalization
description: TRAP (s74, fence_lost_response): pr_warn %llx prints 0x8ef086a7fd6c4ea; normkey prints 0x08ef086a7fd6c4ea. Same key, unequal strings — normalize BOTH…
metadata:
  type: feedback
tags: [harness, scsipr, pr-key, assertions]
---

# A PR key from the kernel log and a PR key from the platter dump are not the same string

The kernel prints keys with `%llx` — unpadded. `tests/fence_crash_cuts.sh` and
`tests/fence_lost_response.sh` carry:

    normkey() { printf '0x%016x' "$(( $1 ))"; }

which zero-pads to 16 hex digits. For any key whose top nibble is zero the two
render differently:

    kernel  victim_key=0x8ef086a7fd6c4ea      (15 digits)
    normkey           0x08ef086a7fd6c4ea      (16 digits)

Comparing them with `ck` produces:

    FAIL the witness names B1's key as the victim
         got=0x8ef086a7fd6c4ea want=0x08ef086a7fd6c4ea

— a confident FAIL about identity binding, from two spellings of one number.
It is intermittent by construction: roughly one key in sixteen has a zero top
nibble, so the same assertion passes lap after lap and then fails.

## The rule

Normalize **both** sides of any key comparison, never just the expected one:

    ck "..." "$(normkey "$(desc_field "$wit" victim_key)")" "$(normkey "$VKEY")"

The same applies to any value crossing from a `pr_warn`/`printk` into an
assertion against a value read from the disklock table or from `sg_persist`:
the log's formatting is not a contract, and `key_present()` already normalizes
its needle for exactly this reason.
