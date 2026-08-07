---
name: demoter-predicate-self-exemption-invariant
description: INVARIANT: any "is a foreign drain active?" test must check self-ownership FIRST. Dropping it cost cache_coherency 0/32, posix_multi 1/32 at 32/caw.
metadata:
  type: reference
tags: [demoter, dlm, invariant, regression, coherency, predicate]
---

# INVARIANT: the foreign-drain predicate must self-exempt FIRST

`xfs/xfs_mxfs_dlm.c`, `mxfs_foreign_demoter()`. Anything answering "is another
task draining this inode, so should I defer?" MUST return false when `current`
owns ANY claim slot, before looking at whether some other slot is occupied.

## The two spellings and why they differ

Original one-slot form, used inline at 6 sites:

    ip->i_dlm_demoter && !mxfs_is_demoter(ip)

`mxfs_is_demoter()` is true if `current` owns slot 1 OR slot 2, so the second
clause is a self-exemption covering both slots.

The broken generalisation (sess26 first cut):

    (d1 && d1 != current) || (d2 && d2 != current)

Diverges in exactly one state: **slot 1 foreign, slot 2 == me.** Original says
"no foreign drain to defer to" (because I am myself a drain). The broken form
says "yes, defer" — so a live release drain abandons its OWN reload because a
peer drain exists. That state is ordinary: two concurrent drains on one inode
were measured 30-152 times per 32-node run.

## Measured cost of getting it wrong (32/caw, v0.11.222)

| criterion | broken predicate | corrected |
|---|---|---|
| cache_coherency | **FAIL 0/32**, timed out at its 60 s budget | PASS 32/32 654/654 **26s** |
| strong_consistency | FAIL 25/32 | PASS 32/32 |
| posix_multi | **FAIL 1/32** | PASS 32/32 80/80 |
| mmap_coherency | PASS | PASS |

Note the shape: `cache_coherency` presented as a TIMEOUT (`0/32
NO_TERMINAL_RECORD`), which looks exactly like the "one wedged node fakes a
broken filesystem" pattern from sess24 and invites chasing a node fault. It was
not a node fault. Before blaming infrastructure for a barrier criterion reading
0/32, check whether a predicate on the reload/defer path changed.

## Correct form

    if (d1 == current || d2 == current)
            return false;           /* I am a drain — never defer to another */
    return d1 != NULL || d2 != NULL;

This keeps the original's self-exemption AND fixes the real blindness it had:
the one-slot spelling reads FALSE when slot 1 was released while slot 2 is
still draining, which is reachable because the two drains do not finish in
claim order.
