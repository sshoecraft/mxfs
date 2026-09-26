---
name: reference-2node-caw-runs-on-the-qnap-lun-via-mxfs-dev-and-cawd
description: 2-node CAW runs on the QNAP LUN: MXFS_DEV=<qnap by-id> ./run.sh 2 cawd prep_cluster. SCST is down (backing images deleted); QNAP does CAW.
metadata:
  type: reference
tags: [caw, rig, qnap, scst]
---

Since clyde's 2026-09-21 boot scst.service fails: /etc/scst.conf names /home/steve/disk-1.img and disk-2.img, which no longer exist. So the caw (mpatha) and cawd/cawp (SCST portal .1/.2) defaults are dead devices. Left alone deliberately (unknown whether the images were removed on purpose; SCST has wedged this host before).

The QNAP LUN (wwn-0x6e843b6393a5a6ed918bd4f4fdb8e7d6, the same one the TCP rig and the platform pairs use) implements COMPARE AND WRITE: sg_vpd -p bl says "Maximum compare and write length: 1 blocks", 512-byte blocks. It rejects the FUA bit on READ(16) (ILLEGAL REQUEST, ASC 0x24), so tools/caw_verify (always FUA) fails its pre-read there; MXFS falls back from that itself.

run.sh takes DEV from MXFS_DEV for every condition and nothing gates CAW on SCST, so:
  MXFS_DEV=/dev/disk/by-id/wwn-0x6e843b6393a5a6ed918bd4f4fdb8e7d6 ./run.sh 2 cawd prep_cluster
mounts test1/test2 with force_transport=0 (transport=caw), converged at active_count=2 in ~70 s. Label it cawd (direct in-guest iSCSI) so board cells are not recorded under the multipath 'caw' condition.
Harnesses that assume a TCP lock master (P7S-BAST-FIRE master selection) must be given a CAW mode; live_holder_wait.sh has one (0.89.92).
