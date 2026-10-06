---
name: reference-on-dm-multipath-mxfs-sends-caw-to-one-path-itself-and-pr-registration-fans-out-to-every-path
description: On mpath, CAW/FUA passthrough goes to ONE path sdev MXFS picks (dm never resends it); PR register goes via dm to ALL paths and fails whole if one is…
metadata:
  type: reference
tags: [mpath, caw, scsipr, dm-multipath]
---

Two facts about MXFS on a dm-multipath map that a design or a test plan gets wrong if it assumes "dm-multipath handles it" (measured/read 2026-10-04, 0.90.44):

**COMPARE AND WRITE and the FUA read/write passthroughs do not go through dm.**
`mxfs_bdev_to_sdev` (pal/linux/kern.c) resolves the dm device to ONE underlying
path's scsi_device (by LBA-0 content among the map's slaves, cached per dev_t)
and the CDB is sent to that sdev. When that path dies the command returns a
transport error to MXFS; nothing resends it. The resend is MXFS's own:
`caw_slot_ex`'s retry loop in dlm/dlm_caw.c (5 retries, 10..200 ms backoff),
which re-resolves to a live path once the dead sdev goes transport-offline.
So "a CAW applied by the target whose answer was lost" is re-sent by MXFS with
the same compare image and miscompares against its own write. The disklock
heartbeat (`hb_cas_own_slot`) already treats an I/O error as indeterminate and
re-reads; `caw_slot_ex` did not until 0.90.44 (P-CAW-ANSWER-LOST-LANDED).
The CAW path can differ from the path dm is using for ordinary I/O.

**Persistent-reservation REGISTER goes through the dm device's pr_ops**, and
drivers/md/dm.c `dm_pr_register` issues it on every path and unregisters all
of them if any one fails. Consequences: a registration made with all paths up
lands on every nexus (hence 2N registrations for N nodes on two paths), and a
mount attempted while one path is down is refused outright
("SCSI persistent reservation register failed ... 65536" = host byte
DID_NO_CONNECT; mount rc 32). A path's registration survives the path going
down and coming back (same I_T nexus), so only a path absent at REGISTER time
lacks one. An unregistered path that becomes active answers RESERVATION
CONFLICT, which dm-multipath does not treat as a path error.

How to apply: when reasoning about a path fault, ask separately what happens to
(a) bio I/O through dm, (b) passthrough commands on the one resolved path,
(c) PR commands fanned out by dm. To inject "command applied, answer lost",
drop only host-to-guest frames on the path's tap (`scripts/san_net.sh mute`).
