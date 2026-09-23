---
name: trap-an-order-comparison-between-two-xfs-inode-generations-is-a-coin-flip-and-a-poison-gated-on-it-kills-a-live-open-successor
description: TRAP (s171, 0.89.76): two gates ordered random XFS generations (evict-ring poison, recycle-gate adopt); each was a coin flip on a reused number. Ask…
metadata:
  type: feedback
tags: [xfs, generation, eviction-ring, recycle, d0977, incarnation, poison, trap]
---

# An order comparison between two XFS inode generations is a coin flip, and a gate built on it fails half the time on a reused number

Run 98c3ef65 session 66 (lap labels s171*, s172*), fixing
D-TCP-OPEN-UNLINK-HELD-FD-READS-EMPTY-AFTER-PEER-UNLINK-S170F and
D-TCP-RECYCLE-GATE-ADOPTS-A-PEERS-NEW-INCARNATION-ON-A-COIN-FLIP-S171C.

## The fact

`xfs_init_new_inode` draws every incarnation's generation with
`get_random_u32()` (deliberately, sess28: a recycled shell must not inherit
the stale gen). `xfs_ifree` bumps the freed image's gen by exactly one.
So the ONLY order relation that means anything is "gen and gen+1 are the
same lineage across one free". Any `<`, `<=`, `(s32)(a - b) > 0` between the
generations of two incarnations is a coin flip.

## Instance 1 — the eviction-ring consumer (`mxfs_dlm_evict_inode_cb`)

Gate was `i_generation <= freed_gen` ("at or behind the freed incarnation");
for an open shell it set the poison. `tests/d0977_open_unlink_tcp.sh` arm B
reuses one number for every victim: B closed incarnation A, the peer freed it
and created successor C on the same number, B opened C (recycling its shell
in place), then A's free entry reached B from the ring:

`EVICT-RING-FLAG ino=2127 incore_gen=2736779274 freed_gen=3992201783 opens=1 poisoned=1`

C's random gen was below A+1 for victims 2, 4, 6 of six (2 and 4 were open
at delivery and read -ESTALE; 3 and 5 drew above and were never flagged).
Filed as data loss and blamed on an unrelated change of the same build.

## Instance 2 — the recycle gate (`xfs_iget_recycle`, P-RECYCLE-GATE)

Adopt was `(s32)(disk_gen - incore_gen) > 0` ("di_gen only moves forward").
14 of 14 captured decisions tracked the numeric order. The one adopt=0 that
met live descriptors: B's fresh open of the peer's new valid file on a reused
number recycled a poisoned shell, kept the dead incarnation, the grant-time
reload found the mismatch with opens=2, poisoned it, and the FIRST read of a
valid file returned -ESTALE (s171c arm C, ino 4241).

## The rule

A gate that receives a generation asks "is this THE incarnation" —
equality, allowing the single xfs_ifree bump — never "is it older". The one
legitimate lag a node can see on its own lineage is platter == incore - 1
(its own free not yet destaged; the ino 1862 autopsy), and that is an exact
signature, not an order. Grep `i_generation <=`, `_gen <=`, `disk_gen <=`,
`(s32)(...gen...) > 0` when a reused-number failure alternates between laps
or victims: alternation at ~50% is the signature. The tree had already
learned this once (`mxfs_typeflip_skip_same_incarn`, sess27) and still had
two more.
