---
name: trap-bare-run-sh-prep-on-the-qnap-2node-rig-needs-mxfs-dev-and-node-list-exported
description: TRAP (sess513): `./run.sh 2 tcp prep_cluster` without MXFS_DEV + MXFS_NODE_LIST fails 'sda claimed by dm-1' and leaves the nodes unmounted; use tests…
metadata:
  type: feedback
tags: [rig, trap, prep, qnap, sess513]
---

# Bare `run.sh prep_cluster` on the 2-node QNAP TCP rig (sess513, 2026-09-05)

A rig-runner was told to run
`MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster` directly. Without the
environment the chain driver exports —

    export MXFS_NODE_LIST=test1,test2
    export MXFS_DEV=/dev/disk/by-path/ip-192.168.1.4:3260-iscsi-iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772-lun-0

— run.sh picks the fleet default `/dev/sda` and fails in 13-20 s with
`FS_PREP_FAIL: /dev/sda (sda) is claimed by: dm-1 — it is a member of a device-mapper
map, not a free LUN`, AFTER it has already unmounted / unloaded the nodes. Every
harness that follows then exits in 1 s with `INFRA: precondition not met (A='<id>' B=' ')`.
Three wasted rig steps (sess513_prep_{a,b,c}.log).

Rule: on this rig never call run.sh prep by hand; drive everything through
`tests/sess511_chain_0756.sh <label> <steps>` (steps 11 = held rejoin arm, 12 = delayed
sameboot arm 1 were added for this), which exports both variables. If a one-off prep is
unavoidable, export the two variables first.
