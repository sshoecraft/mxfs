---
name: technique-model-check-the-drbd-cas-lock-and-never-clip-a-counter-in-the-model
description: tests/drbd_cas_lock_model.py checks the DRBD swap lock under per-disk landing; a clipped ticket faked a bakery violation; run --broken as negative co…
metadata:
  type: reference
---

`tests/drbd_cas_lock_model.py` exhaustively checks the two-host lock under the DRBD compare-and-swap emulation (pal/linux/drbd.c, mxfs_drbd_lock) with DRBD's storage model: each register write lands on each host's disk at its own moment, completes for its writer only when both disks hold it, and each host reads its own disk. Checks mutual exclusion, no deadlock, and no starvation of participant 1.

- `python3 tests/drbd_cas_lock_model.py` (the one-bit lock, version 2), `--bakery` (the old Lamport bakery, a control), `--broken` (reads the peer before the raise completed: MUST report a violation; this is the negative control proving the checker can find one).
- TRAP: the first bakery model clipped tickets at a cap (min(peer+1, 3)); two tickets then tied at the cap and the checker reported a mutual-exclusion violation that the real code cannot have (it refuses a ticket past MXFS_DRBD_TICKET_MAX with -EOVERFLOW and releases). Model a bound the way the code enforces it (fail the operation), never by saturating the value.
- Any change to the lock's entry/exit order, the register fields, or the release ordering (the deferred release in rel_work) must be re-modelled here before it reaches a host.

Provenance: 0.90.101, the change from the bakery to the one-bit lock to halve heartbeat swap latency on the physical pair.
