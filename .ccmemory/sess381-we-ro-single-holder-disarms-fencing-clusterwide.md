---
name: sess381-we-ro-single-holder-disarms-fencing-clusterwide
description: sess381 ROOT CAUSE, measured: ONE node's 0.49s clean unmount releases the LUN's only WE-RO reservation and disarms fencing cluster-wide. WE-AR fixes…
metadata:
  type: project
tags: [sess381, scsipr, fencing, we-ro, we-ar, root-cause, 381, 379, measured]
---

# sess381 — WE-RO is a SINGLE-HOLDER reservation, and that bricks the filesystem

Answers step 0 of `D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379`.
Split into two new criticals:
`D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381` and
`D-FENCE-PRECONDITION-FAILURE-RECORDED-TERMINAL-381`.

## The chain (every step measured, 32/caw, 0.15.10 sv F73F08F0690BB7561EF6930)

1. MXFS reserves the shared LUN with **type 0x05 WE-RO** (`pal/linux/user.c:1317`,
   kern.c equivalent). WE-RO is a **single-holder** type. `PRIN READ FULL STATUS`
   on the healthy cluster: `holder_key=0x524c049d`,
   `iqn...:test1-mxfs-node,i,0xc00003d0200`, 64 keys / 32 distinct. **One nexus
   is the holder; the other 63 registrations are not.**
2. `mxfs_scsipr_reserve()`'s return value is **DISCARDED at all four call sites**
   (`dlm/v5_mount.c:4320`, `:4031`, `dlm/mount.c:1980`, `:2191`); a RESERVATION
   CONFLICT is read as "someone else holds it, fine".
3. `pal/linux/xfs_super.c:~1727` unregisters the node's key **unconditionally** at
   put_super (made mandatory by `D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377`).
   SPC-4 **releases** a `*_REGISTRANTS_ONLY` reservation when the holder's
   registration is removed.
4. **MEASURED:** `umount /mnt/shared` on test1 alone — `real 0m0.056s`, 0.49s wall
   — took the LUN from `holder_key=0x524c049d ... keys=64 distinct=32` to
   **`NONE HELD  keys=62 distinct=31`**, with 31 nodes mounted and registered
   throughout. Still NONE HELD across a 30 s poll. **Nothing re-reserves.**
5. **MEASURED consequence:** ~30 min later `virsh destroy test3`. Death at t+66 s.
   Elected prover test32:
   `P236-FENCEKIND node=1268531449 kind=NO_RESERVATION(8) proves_excl=0 gen=2121 rc=0`
   `P238-FENCE-UNPROVEN slot=2 ... Recovery is BLOCKED on unproven exclusion`.
   The other 30 survivors: `P236-FENCE-ATTEMPT-BUSY`.
6. **The filesystem is then permanently unmountable.** Remounting test1 gave four
   × `P236-CLAIM-UNCERTIFIED slot=2 ... stage=1 kind=0` then ABORT at 36.4 s.

## The admission gate is structurally blind to it

`mxfs_scsipr_validate_admission()` (the sess378 P303-FENCECAP gate) refuses the
mount unless WE-RO is HELD — but `dlm/v5_mount.c:4320` calls
`mxfs_scsipr_reserve()` on the line **immediately before** it. The gate validates
a reservation it just created. Proof: test1's failed remount logged
`P303-FENCECAP-OK ... WE-RO held ... PREEMPT AND ABORT issuable` while two
independent observers read NONE HELD immediately before and after. There is **no
periodic reservation-health check anywhere in the tree**, so 31 nodes believed
fencing was armed for the 30 minutes it was not.

## Why NO_RESERVATION should never have been terminal

`dlm/scsipr.c:437` returns `MXFS_FENCE_KIND_NO_RESERVATION` **before** the PROUT
PREEMPT AND ABORT at `:459`. No command is submitted, nothing is consumed, the
victim key stays registered. It is a pure **precondition** failure — yet it is
published as a durable stage=1 guard that nothing ever re-opens.

## THE FIX PROPERTY, PROVEN ON THE REAL TARGET

`tests/pr_all_registrants_semantics.sh` (scratch key from an unmounted node, so
no MXFS registration is touched):

```
REGISTER 0xdeadbeef            -> keys 62->63
RESERVE --prout-type=7         -> "Key=0x0  LU_SCOPE  Write Exclusive, all registrants"
UNREGISTER the holder key      -> keys 63->62
READ RESERVATION               -> STILL "Write Exclusive, all registrants"   <== WE-RO would be gone
KA on /dev/sda, KB on /dev/sdb, KA RESERVE type7, then KB RESERVE type7 -> rc=0 GOOD (not CONFLICT)
RELEASE by any registrant      -> works; raises Unit Attention to other initiators
```

Target supports it: `P303-FENCECAP type_mask=0xea01` → REPORT CAPABILITIES
`resp[4]=0xEA`, **bit7 = WR_EX_AR set** (bit layout documented at
`pal/linux/kern.c:3181`).

Two behaviours to code around, both measured: under WE-AR **READ RESERVATION
reports Key=0x0** (no single holder key), and **RELEASE/preempt raises a Unit
Attention** that the next PRIN on other initiators sees as a failure.

## Harnesses (repo, re-runnable)

- `tests/pr_reservation_ownership_probe.sh <observer> [dev]` — read-only; prints
  holder key + initiator IQN + key counts, or `NONE HELD`.
- `tests/pr_all_registrants_semantics.sh <spare-host> <observer> [dev]`
  (`PART2=1` for the second-registrant RESERVE test). Restores pre-state.

Full RULE-5 ruling: ccmemory `ccloop-c7ee71c6-sess381-GPT-ruling-we-ar-fencing-lifetime`.
