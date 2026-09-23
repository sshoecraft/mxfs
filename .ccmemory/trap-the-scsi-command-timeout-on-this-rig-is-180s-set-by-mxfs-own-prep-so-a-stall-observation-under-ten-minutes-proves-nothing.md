---
name: trap-the-scsi-command-timeout-on-this-rig-is-180s-set-by-mxfs-own-prep-so-a-stall-observation-under-ten-minutes-proves-nothing
description: TRAP (s84): /sys/block/sda/device/timeout is 180 here (set by verify_infra.sh), not 30; libiscsi needs ~3 expiries before EH, so 540s+ before any res…
metadata:
  type: feedback
---

# A stalled-I/O observation on this rig needs ten minutes, not four

`D-A-BYSTANDER-INITIATOR-HANGS-FOREVER-...` was opened on this reasoning: the
bystander's writer sat in D state for 3m39s, "far longer than the 30 s SCSI
command timeout, so the block/SCSI timeout path did not rescue it either".

**The command timeout on this rig is 180 s, and MXFS sets it itself.**

```
/sys/block/sda/device/timeout -> 180
scripts/verify_infra.sh:87       echo 180 > /sys/block/$dev/device/timeout
tools/prep_tcm_node_scst.sh:58   echo 180 > /sys/block/$DEVICE/device/timeout
```

(The `99-vmware-scsi-udev.rules` 180 s rule matches VMware virtual disks and
does NOT apply to the iSCSI LUN — do not credit it.)

So 3m39s = 219 s is **1.2 expiries**. And `iscsi_eh_cmd_timed_out()` in
`drivers/scsi/libiscsi.c` answers the FIRST expiry with "Command making
progress — asking scsi-ml for more time" essentially always. At 219 s the
initiator had made exactly one decision and reset the timer. Nothing had failed
to rescue the command; the watching stopped before the stack's first real
opportunity.

**The arithmetic any such observation has to respect on this rig:**

- one expiry = 180 s (the device timeout);
- the earliest the SCSI error handler can be let in is ~3 expiries = **540 s**,
  because the ladder is: progress → an older task progressed → send a nop-out →
  only then `SCSI_EH_NOT_HANDLED`;
- EH's own budget on top, from `/etc/iscsi/iscsid.conf`: `abort_timeout 15`,
  `lu_reset_timeout 30`, `tgt_reset_timeout 30`;
- `node.session.timeo.replacement_timeout` (recovery_tmo) is 120 and is about
  a FAILED CONNECTION, not a stalled task — it does not apply when the session
  is healthy and only one task was aborted at the target.

So a single full opportunity is ~615 s. **A window under ten minutes cannot
distinguish "never rescued" from "not yet".** Derive the observation from these
numbers and assert the device timeout at the top of the harness — a budget that
rests on a tunable has to check the tunable
(`tests/lu_reset_bystander_eh.sh` does).

Worth its own thought some day: a 180 s command timeout means a stuck command
is invisible to this cluster for three minutes, on a filesystem whose fencing
reasoning assumes bounded I/O.
