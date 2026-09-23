---
name: trap-a-raw-forge-write-to-the-shared-lun-is-refused-while-another-initiator-holds-the-reservation
description: TRAP (s91b): recov_forge mkguard from an unmounted node failed SG_IO status=24 (RESERVATION CONFLICT) because the just-destroyed peer still held the…
metadata:
  type: feedback
tags: [rig, harness, scsi-pr, recov_forge, reservation]
---

# Who may write the LUN raw: the reservation holder, or nobody holding it

## What happened

`tests/authtail_mount_unwind.sh` lap s91b unmounted the survivor first and then
destroyed the peer, and two seconds later ran the forge from the unmounted
survivor:

```
recov_forge: this target rejects FUA in the CDB (ILLEGAL REQUEST 24/00);
             reissuing without it for the rest of this run ...
SG_IO write failed: status=24 host=0 driver=0 sense=00/00/00 fua=0
auto fs_gen=0xf1dc3e7d (from slot 0)
RC=1
```

`status=%u` is decimal (`tools/recov_forge.c:338`), so 24 is 0x18 —
**RESERVATION CONFLICT**, not the FUA problem the first line is about. The FUA
fallback had already fired and the retry was `fua=0`; the write was refused by
the target's persistent reservation, with no sense data.

## Why

The LUN is held WRITE EXCLUSIVE through SCSI PR. Only the reservation HOLDER may
write it; a registered non-holder may not, and an unregistered initiator
certainly may not. In this ordering the destroyed peer was still the holder — a
VM `destroy` kills the guest instantly but the appliance purges the key with the
iSCSI SESSION, on its own schedule, which is far longer than the two seconds the
lap waited.

Reads are unaffected, which is what makes this confusing: `recov_forge dump` and
`recov_forge save` both succeeded from the same unmounted node in the same lap.
Only the write was refused.

## The rules that follow

- **Issue a raw LUN write from a node that is mounted and holds the
  reservation**, or from a state where NOBODY holds it.
- `tests/d513_fswide_abort_preserves_death.sh` forges from an unmounted survivor
  and works — because it destroys the victim FIRST, so the still-mounted
  survivor fences and takes the reservation, and its own later unmount releases
  it. Nothing is held when the forge runs. Copying its forge step into a harness
  with a different node order reproduces this failure.
- A cleanup write on the way out (restoring a forged slot) has the same problem
  and is worse, because a terminal forged record left behind refuses every later
  mount including the next prep. Give it a bounded retry so it survives the
  appliance's purge delay, and report the tries and the wall so a slow purge is
  visible.
