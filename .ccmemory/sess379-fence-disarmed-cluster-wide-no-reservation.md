---
name: sess379-fence-disarmed-cluster-wide-no-reservation
description: sess379 CORRECTION: the bricking fence failed with kind=NO_RESERVATION(8) — the LUN carried no WE-RO reservation, disarming fencing cluster-wide, not…
metadata:
  type: project
tags: [sess379, critical, fence, reservation, 379, correction]
---

# sess379 correction — the fence failed on NO RESERVATION, not the absent key

Amends `sess379-dirty-slice-departure-bricks-the-filesystem`. The ledger entry
**D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379** has been corrected;
read this before acting on the earlier memory's mechanism.

## What the recovery owner's own journal says

test30 (`3668433354`), the node that took the recovery lease:

```
07:21:36  heartbeat from unknown node 2569023191 (192.168.120.107) — new peer
07:21:37  lease: node 2569023191 transitioned to ACTIVE
07:22:14  [the 28-of-32 mass-unmount storm starts]
07:24:19  node 2569023191 (slot 9 inc 7860688283116785074) LEASE EXPIRED/DIED — fencing; recovery starting
07:24:19  P236-FENCE-INTENT ... fencing intent is DURABLE; the PREEMPT AND ABORT may now be issued
07:24:19  P236-FENCEKIND node=2569023191 kind=NO_RESERVATION(8) proves_excl=0 gen=15402 rc=0
07:24:19  P238-FENCE-UNPROVEN slot=9 ... kind=NO_RESERVATION(8) — Recovery is BLOCKED on unproven exclusion
07:24:19  P164-DEAD-NOTE / P163-RECOVERY-PENDING slot=9
```

`NO_RESERVATION(8)` is `dlm/scsipr.c`'s **P-PR-NORESV** branch, which fires
*before* the victim-key test:

> A reservation must be HELD for deregistration to exclude anyone. Under WE-RO
> the target rejects writes from non-registrants at command-processing time —
> but only while the reservation exists.

The on-disk guard agrees: `resv_type=0x00`.

## Why this matters more than the key

**At that moment the LUN carried NO WE-RO reservation at all — so fencing was
impossible for EVERY node, not just this victim.** On a healthy 32-node cluster
a reservation IS held (verified after the re-prep: `sg_persist --in
--read-reservation` → `Key=0x908cbcdd`, `LU_SCOPE`, `Write Exclusive,
registrants only`, 64 keys). So the reservation exists in normal operation and
was **lost across the mass departure**.

The sess378 admission check `P303-FENCECAP` validates "WE-RO held" **at mount
time only**. The capability it proves can evaporate afterwards with no
detection — there is no periodic reservation-health check.

## The full chain, all measured

1. A node's unmount stalls past its lease under
   **D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B** — so peers declare a merely
   **SLOW** node **DEAD** and start recovery. (Node 2569023191 joined at
   07:21:36 and was declared dead at 07:24:19, right through the storm.)
2. The fence proves nothing: `kind=NO_RESERVATION(8)`.
3. The recovery guard is left at `stage=1` with a **live** owner (test30, healthy
   throughout) that can never advance.
4. MXFS *also* retires the victim's PR key unconditionally at `put_super`, so
   the mounting node's later `PREEMPT AND ABORT` has no key to preempt either
   (`KEY_ABSENT_UNPROVEN`, `P236-CLAIM-UNCERTIFIED`).
5. The mount **admission barrier** then refuses every new mount, permanently —
   it requires the slice to be REPLAYED and does not route around it to any of
   the 27 free slots.

Result: 28 of 32 nodes could not rejoin their own filesystem, repeatedly over
10+ minutes, with 4 healthy peers mounted. Only `mkfs_mxfs` recovers it.

## First thing to establish next session

Who owns the WE-RO reservation, what happens to it when that node departs, and
why the LUN was unreserved at 07:24:19. If it is held by one member and simply
lost on departure, **any** departure of that member disarms fencing
cluster-wide — and that outranks everything else in this entry. Add a periodic
reservation-health check regardless.
