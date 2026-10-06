---
name: trap-a-raw-pr-out-register-without-aptpl-turns-persistence-off-for-the-whole-lu
description: TRAP (0.90.45): SCST takes APTPL from the LAST REGISTER; a raw probe/REGISTER with data[20]=0 cleared it and the next mount was refused P303-FENCECAP…
metadata:
  type: feedback
tags: [scsipr, mpath, scst, aptpl]
---

**What happened.** 0.90.45 moved persistent-reservation REGISTER off the block layer's `pr_ops` and onto raw `PERSISTENT RESERVE OUT` CDBs sent to each multipath path's `scsi_device` (pal/linux/kern.c `mxfs_prout_path`). The first build left the parameter list's byte 20 at 0. Every mount was then refused:

    P303-FENCECAP 'mxfs' ptpl_c=1 ptpl_a=0 ...
    P303-FENCECAP-NOPERSIST ... PR state is NOT persisting through power loss
    TCP mount REFUSED (-1)

and `run.sh` reported only `PREP FAIL (form test1):`.

**Why.** `sd_pr_register` always sets APTPL (bit 0 of byte 20). SCST's `scst_pr_register` does `dev->pr_aptpl = aptpl` on EVERY register, including the nexus-local probe `REGISTER(rk=K, sark=K)` and an unregister, so one REGISTER without the bit turns persistence off for the whole logical unit, and MXFS's admission check (REPORT CAPABILITIES, PTPL_A) refuses to mount on it.

**How to apply.** Any hand-built PR OUT REGISTER (SA 0x00) or REGISTER AND IGNORE (SA 0x06) must set `data[20] = 0x01`, exactly as the in-tree `sd_pr_out_command` caller does. PREEMPT / PREEMPT AND ABORT pass 0 there, as sd does. When a prep fails with an empty reason after touching PR code, read the node's dmesg for `P303-FENCECAP` before anything else.

Related: the row's own log line after a failed prep was the PREVIOUS run's (`trap-a-board-chain-read-back-shows-the-standing-board-so-a-run-sh-that-never-started-reads-green`): `laps.sh` picks the newest evidence directory, which is the old one when the row never started.
