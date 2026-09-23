---
name: trap-a-per-lun-exclusive-reservation-has-more-than-one-recovery-depending-on-it
description: MEASURED sess580: a node returning alone runs TWO recoveries under ONE per-LUN PR gate; completing either used to lift it under the other, stranding…
metadata:
  type: project
tags: [fencing, scsipr, recovery, dlm, architecture]
---

## The shape nobody had counted

There is **one SCSI PR reservation per LUN**, but a node can be executing **more than one recovery under it at once**. The case that produces it is ordinary, not exotic:

A node returns alone after a crash. It must recover **its own previous incarnation**, and it must **fence the peer that had been recovering it**. Both run under one per-LUN exclusive-write gate, because there is only one reservation to have.

And the second of those is not incidental to the first. A safe takeover has **two classes of stale writer** to exclude: the original journal owner, *and* the previous recovery executor. Fencing the peer that was recovering you is part of taking that recovery over, not an unrelated act.

## What went wrong

`v5_gate_restore()`'s own comment encoded the wrong cardinality — *"never called while **the gate's recovery** is still pending"*, **singular** — and the completion path acted on it: any recovery publishing converted the single-holder Write Exclusive back to WE-AR. So the first recovery to finish removed the exclusion the second was still running under. The second then refused to replay anything for ever (correct, fail-closed) and its mount never completed. The only surviving node could not mount the filesystem.

Measured to the same second (`tests/evidence/20260911T160134Z_d0932own_s580i`): gate installed 16:07:25 → first recovery published 16:07:43 → `P-PR-GATE-RESTORE site=recovery-complete` 16:07:43 → `P239-EXCL-LAPSED slot=1` 16:07:43, then once a second for 72 s.

## The fix, and the three wrong turns it avoided

Fixed in 0.82.4 by an explicit dependent set: a recovery registers that it depends on the gate *from the same evidence it proceeds on*, completion releases its own dependency instead of restoring the reservation, and the restore lands only when the set empties. Released by completion or a recorded block, **never by a timer** — an unjustified release is the exclusion itself; retention only costs availability and says so in the log. Verified: exclusion-lapse events 58 → **0**.

Three moves that look right and are not:

1. **Do not relax the check to accept WE-AR.** A gate certificate is issued exactly when the victim's key was *already absent* (`already purged by the target`), so "victim key absent" proves nothing there — a re-registered victim could write under WE-AR. The single-holder gate is the only thing keeping it out. `mxfs_fence_kind_resv_type_ok()` encodes this deliberately: `PREEMPT_ABORT_DONE` and `BOOT_SUCCESSION_ABSENT` accept any type excluding non-registrants, `EXCLUSIVE_WRITE_GATE` demands exactly the single-holder type.
2. **Do not compare against the certificate's original prover key.** If the old prover still held the reservation, the new executor could not write at all. That converts accidental progress into guaranteed refusal and repairs nothing.
3. **Do not use a bare refcount.** A count cannot say which recovery pins the gate, whether it has outstanding I/O, or whether a cancelled worker left a publication obligation. Make the explicit set authoritative.

## Settle integrity-vs-liveness BEFORE choosing a fix here

The question "could restoring the reservation early let someone write?" is answered by `dlm/disklock.h`'s stage contract, not by a teardown message:

- `victim fenced := GUARD + descriptor` / `grants released := stage >= GRANTS_RELEASED` / `recovery complete := sector zeroed`. **Only the last releases a peer's deferred purge.**
- The slice is protected by the **on-disk GUARD record**, not the reservation: `claim_slot` never takes a GUARD slot, `guard_slot` refuses a slot carrying a descriptor, and nobody may mount on it or lay a fresh journal over the slice until CONSUMABLE.
- At GRANTS_RELEASED every replay stage is already past, so the only outstanding obligation is the purge.

So this was liveness, and no exclusion semantics needed changing. A different answer would have demanded a different fix.

## Still owed on this axis (consult-named, not yet exercised)

- The purge must be **generation-safe** — it must name which journal generation and records it deletes, or it can erase a new incarnation's journal or reused space.
- **Control-plane publication must be fenced too**: a stale executor can lose PR write access and still send grant-release or completion messages. "Check reservation, then publish" is not sufficient against a concurrent takeover.
- Two nodes re-proving gates concurrently cannot both be write-capable owners; that needs one cluster-authorised gate owner per LUN, not cleverer per-recovery retries. `pr_gen` is not a leadership term.
