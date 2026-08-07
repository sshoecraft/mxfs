---
name: ccloop-c7ee71c6-sess93-fenced-victim-CAN-reregister-MEASURED
description: sess93 MEASURED: a PREEMPT-AND-ABORTed node re-registers and writes to the shared LUN seconds later. The fence certificate has a shelf life; MXFS's o…
metadata:
  type: reference
tags: [sess93, MEASURED, rig, scsi-pr, fencing, D-FENCED-VICTIM-MAY-REREGISTER, critical, probe]
---

# sess93 — a fenced victim CAN re-register and write. Measured, not argued.

`tests/pr_reregister_probe.sh`, 32/caw, at the SCSI layer with MXFS bypassed.
Victim test32 (key `0x37e3d796`), preemptor test1 (key `0x434d2436`, also the
WE-RO reservation holder), scratch LBA 131087.

```
1. baseline write (0xa5)                     rc=0  SUCCESS
2. PREEMPT AND ABORT of 0x37e3d796           rc=0  -> 0 descriptors left
3. write after the fence (0x5a)              rc=1  REFUSED   <- exclusion works
4a. REGISTER_AND_IGNORE, fresh key 0xfeed0001 rc=0  ACCEPTED BY THE TARGET
4b. write as a fresh registrant (0x33)       rc=0  ACCEPTED — bytes landed
```

Step 3 is the important control: exclusion is REAL at the instant of the P&A,
so the certificate says something true. Step 4 is the defect: the truth expires
and nothing enforces the interval.

## What this means for the 0.11.422 fence-evidence channel

The certificate authorises ~8 s of in-place foreign log replay over shared XFS
metadata. During that window the ONLY thing keeping a fenced-but-alive victim
off the LUN is `mxfs_scsipr_self_check` noticing its own key is gone and
force-shutting the filesystem down (`P131-SELF-FENCE`, explicitly "no auto
re-register"). **That is cooperative.** It assumes the victim is healthy enough
to schedule — the exact assumption a fence exists to drop. A CPU-starved or
network-partitioned node that missed 31 heartbeat samples is not obliged to
notice anything before its next I/O retry re-registers it.

## Why no existing test caught it

Every fencing criterion kills the victim with `virsh destroy` — a power cut.
The victim is not fenced-and-running, it is GONE, so it never attempts anything
afterwards. The dangerous state has never been produced. This probe produces it
by preempting a **healthy** node's key.

## What it does NOT invalidate

`D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION` and
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION` were about publishing and consuming
**no evidence at all**, and both are genuinely fixed and rig-verified on
0.11.422. This is a distinct defect about how long the evidence stays true, and
it is filed as `D-FENCED-VICTIM-MAY-REREGISTER` (critical) rather than used to
reopen them. Keeping those separate matters: conflating them would make the
closed entries look premature when they are not.

## Next (in the ledger)

1. RULE-5 consult on enforcement before any code — target ACL revocation,
   iSCSI session revocation, or registration-blocking membership. They differ
   in what they demand of the storage stack and the LIO/SCST rig may not
   support all of them. Making the self-fence faster is NOT a fix: any
   cooperative mechanism has the same hole.
2. Measure the exposure window (`P236-FENCE-CERTIFIED` → `P163-RECOVERY-COMPLETE`)
   across runs — it bounds the damage window.
3. Cheap interim, worth doing regardless: re-verify the victim key is still
   absent immediately before each destructive step
   (`D-FENCE-RESERVATION-HEALTH-UNCHECKED`'s mechanism). It catches a
   re-registered victim, though it cannot prevent a racing write.

## Rig facts banked

- `sg_persist` and `sg_inq` ARE installed on the test nodes.
- 64 registered key descriptors for 32 nodes — each node registers on BOTH
  multipath paths (corroborates the sess72 key-view truncation finding).
- Reservation: `type: Write Exclusive, registrants only`, held by the slot-0
  node's key.
- `tools/caw_verify --retry-ua write <dev> <lba> <byte>` is the safe scratch
  write; `--retry-ua` is REQUIRED on dm-multipath or the first attempt eats a
  UNIT ATTENTION. LBA 131087 sits immediately below the disklock table
  (byte 67117056 = LBA 131088) and is the convention `dlm_lock_correctness`
  has used on every board run.
