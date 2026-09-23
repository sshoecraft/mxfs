---
name: trap-32-tcp-condition-device-is-xml-sda-use-mxfs-dev-mpatha-and-mxfs-crit
description: TRAP (sess418): `./run.sh 32 tcp prep_cluster` FAILS on the current fleet (/dev/sda claimed by dm-1) — tcp condition = old LIO tcm_loop rig. Use MXFS…
metadata:
  type: feedback
tags: [rig, tcp, run.sh, multipath, trap]
---

# TRAP: the `tcp` board condition is wired to a rig that no longer exists on this fleet

run.sh conditions (header comment, lines 40-101): `tcp` = condition 1, TCP DLM over the LIO
tcm_loop rig with the shared LUN XML-wired into the guests as /dev/sda; `caw` = condition 4,
CAW over dm-multipath (/dev/mapper/mpatha, dual SCST portal).  The fleet today is the
multipath rig, so on it `./run.sh 32 tcp prep_cluster` dies in prep_fs with:

    FS_PREP_FAIL: /dev/sda (sda) is claimed by: dm-1 — it is a member of a device-mapper map,
    not a free LUN. This deployment condition's rig is not wired on this fleet.

The 32/tcp column's 20 PASS cells are from that older rig/build.

**To exercise the TCP DLM transport on the current fleet:**

    MXFS_DEV=/dev/mapper/mpatha MXFS_CRIT=/src/mxfs/criteria.tcpmp.json ./run.sh 32 tcp prep_cluster

`MXFS_DEV` overrides the per-condition device; `MXFS_CRIT` keeps the results OFF the primary
board (cells are keyed <N>/<dlm> with no rig dimension — running a condition on a different rig
would silently overwrite the column in place; run.sh:103-107 documents exactly this).  The
transport gate in tests/d0286_tcp_wedge.sh / d0287_remaster_measure.sh reads
/sys/module/mxfs/parameters/force_transport==1, which is transport, not rig, so it is satisfied.
