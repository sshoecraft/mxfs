---
name: compiled-rig-heal-verification-state-file-rewrites-and-scsi-timeout-observation-windows
description: Rig traps: verify a heal at the broken layer, a state-file rewrite must keep its fields, and stall windows must outlast the 180s SCSI timeout ladder.
metadata:
  type: feedback
tags: [compiled, rig, iscsi, measurement-integrity, deploy, scsi-timeout]
---

# Rig traps: a verdict taken at the wrong layer, a state file rewritten short, an observation window shorter than the stack's timers

Three notes share one shape: the rig reports success or absence while the property under test was never exercised. Each fix is to check at the layer whose behavior is the subject, and to order checks before destructive steps.

## Healing a partition restores reachability, not the session

[[trap-healing-a-storage-partition-by-removing-the-firewall-rule-does-not-bring-the-path-back-and-the-absence-reads-as-safety]]

- `iscsid` tears a dropped session down at `node.session.timeo.replacement_timeout` = 120 s. A partition long enough to outlast the 62 s dead window plus the fence (180 s) is past that. Removing the iptables rules afterwards restores reachability only.
- A lap that then reads the keys scores "key absent" as safety and "no write from the fenced incarnation" as containment. Both are vacuous: the node simply has no path.
- Required: count sessions (`iscsiadm -m session`), run `iscsiadm -m node --login` (no-op if the session survived), count again, and prove the LUN is readable from that node (direct-I/O single-sector read) before any verdict. Not readable means the lap is VACUOUS, not a pass.
- General: for any "break a path, then heal it" lap, verify the heal at the layer whose return is the subject, never at the layer that was broken. Guard lives in `tests/fence_partition_reconnect.sh` at its reconnect stage.

## A deploy script that reads a state-file field and then drops it

[[trap-module-swap-deploy-dropped-dev-from-marker-and-killed-the-rig-on-its-second-run]]

- `scripts/module_swap_deploy.sh` resolves the LUN from `MXFS_DEV`, else the `dev` field of `.cluster_marker.json`, else `/dev/mapper/mpatha` (nonexistent on the QNAP rig). It rewrote the marker with `jq -n '{nodes, dlm, srcversion, node_list, iso}'`, omitting `dev`.
- The first swap after `prep_cluster` worked; the second fell through to the nonexistent default after it had already unmounted and rmmod'd every node, leaving a SCSI-PR reservation-conflict state that cost a full re-prep.
- The run that breaks is clean and prints `SWAP_OK`; the damage lands on the next run. A script that reads a value from a state file and rewrites the file must write the value back. Fixed in 0.75.118 (`--arg dev "$DEV"`, `SWAP_OK` prints the stored device); verified by two consecutive swaps.
- General: a precondition that can fail goes before the destructive step. Here teardown (step 1) preceded device validation (step 2).

## Stall observations on this rig need more than ten minutes

[[trap-the-scsi-command-timeout-on-this-rig-is-180s-set-by-mxfs-own-prep-so-a-stall-observation-under-ten-minutes-proves-nothing]]

- The SCSI command timeout is 180 s, not 30: `/sys/block/sda/device/timeout` is set by `scripts/verify_infra.sh:87` and `tools/prep_tcm_node_scst.sh:58`. The VMware udev rule does not apply to the iSCSI LUN.
- A defect was opened on a 3m39s (219 s) D-state observation reasoned as "far longer than the 30 s timeout". That is 1.2 expiries. `iscsi_eh_cmd_timed_out()` answers the first expiry with "making progress, more time", so nothing had failed to rescue it; the watching stopped first.
- The ladder: progress, then an older task progressed, then nop-out, only then `SCSI_EH_NOT_HANDLED`: about 3 expiries = 540 s before EH can start. EH adds `abort_timeout 15`, `lu_reset_timeout 30`, `tgt_reset_timeout 30` from `/etc/iscsi/iscsid.conf`. One full opportunity is about 615 s. A window under ten minutes cannot distinguish "never rescued" from "not yet".
- `replacement_timeout` (120) concerns a failed connection, not a stalled task on a healthy session; it does not apply here.
- Derive the observation window from these numbers and assert the device timeout at the top of the harness (`tests/lu_reset_bystander_eh.sh` does). Open question left by the note: a 180 s timeout makes a stuck command invisible for three minutes on a filesystem whose fencing assumes bounded I/O.
