---
name: trap-a-death-test-whose-victim-dies-between-swaps-never-tests-a-lock-held-across-death
description: TRAP (0.90.40 DRBD): death-test passed many times; the victim always died between CAS swaps. A death holding the bakery ticket made the survivor with…
metadata:
  type: feedback
tags: [drbd, death, testing]
---

**What happened.** On 2/net/mesh/drbd the compare-and-swap is a two-party bakery lock on the device. `scripts/drbd_rig.sh death-test` (a `virsh destroy` of an idle-ish victim) passed in every session, because the victim always died between swaps.

`crash_audit` kills the victim under a write stream, and on the board the victim died **holding its ticket**. On the survivor:
- every swap waited 10 s and failed with `EIO` (`P-DRBD-CAS-WAIT-TIMEOUT … peer_ticket=4`);
- the heartbeat failed twice;
- the survivor declared itself dead (`P163-WITHDRAW-STAMP`).

The ticket could be cleared only after a fence certificate, and minting the certificate needs swaps.

**Rule.** For any lock or lease that a peer can hold across its own death, test the death **while it is held**, deterministically, not by hoping a load lands it. Here that is the one-shot knob `mxfs.dbg_drbd_cas_hold_ms`, used by `DEATH_HOLD_TICKET=1 scripts/drbd_rig.sh death-test`. Then check that the survivor clears the lock by proof (`P-DRBD-CAS-PEER-EXCLUDED`) and does not withdraw.
