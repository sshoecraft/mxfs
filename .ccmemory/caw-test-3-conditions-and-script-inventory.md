---
name: caw-test-3-conditions-and-script-inventory
description: MXFS 3 deploy conditions (TCP / FC-sim passthrough / direct iSCSI+CAW). Setup scripts do host infra AND per-VM config, N=1..32. CAW bring-up scripts…
metadata:
  type: project
tags: [caw, scst, iscsi, test-infra, scripts, conditions, 32-nodes]
---

## The 3 deployment conditions MXFS must validate (user framing, 2026-07-05)

Simulating real datacenter shared-LUN deployments using the test VMs. Key
correction: it's ONE shared LUN with N initiators (each host its own nexus/PR
registrant), NOT one LUN per host. CAW (SCSI 0x89) is transport-agnostic (same
over FC/iSCSI; = VMware VAAI ATS). Transport never fakes CAW — the *target*
does (SCST real; LIO fakes; QNAP/vendor = verify with caw_verify).

1. **TCP DLM / commodity block dev (no CAW).** `force_transport=1`. DONE:
   8-node = 100% (showstat 8 tcp). Rig = LIO/tcm_loop.
2. **FC-fabric → physical hosts (CAW).** SCST + per-VM QEMU `device='lun'`
   PASSTHROUGH: clyde is the initiator, distinct target per VM → N sdX on clyde
   → one passed to each VM. Per-VM host session = REAL PR fencing (sess26). The
   "16 (now 32) sdX on clyde" the user remembers = this model; REQUIRED to sim FC.
3. **Direct iSCSI mount, no fabric (CAW).** Each VM runs its OWN iscsiadm login
   to clyde's SCST target → own nexus/PR. 0 sdX on clyde. "Joe sysadmin mounts
   an iSCSI LUN directly." iSCSI carries CAW if the target implements it.

## Requirements (user, 2026-07-05)
- Setup must be END-TO-END: HOST infra AND per-VM guest config. N = 1..32 (NOT 16).

## BUILT 2026-07-05 — CAW bring-up scripts (syntax-checked, NOT yet run)
- **`scripts/scst_setup.sh {setup|status|teardown}`** — HOST: load SCST +
  iscsi-scstd, create vdisk_fileio device `mxfs` (o_direct=1) over disk.img,
  publish iSCSI target `iqn.2026-05.local.mxfs:shared` on 192.168.120.1:3260.
  AUTO-tears-down LIO on same img first. Foundation for BOTH cond 2 & 3. A
  vdisk_fileio dev makes NO local sdX until an initiator logs in.
- **`scripts/scst_wire_passthrough.sh {attach|detach|status} [N]`** — cond 2
  host side: per node K create distinct target `...:nodeK`, clyde loopback
  login → stable /dev/disk/by-path dev → virsh attach device='lun' into testK
  as sda. Distinct targets (not N ifaces) REQUIRED: per-nexus PR + by-path
  collision otherwise.
- **`scripts/caw_cluster_up.sh {direct|passthrough} [N] [dpn]`** — END-TO-END
  orchestrator. Host setup → per-mode wiring → restart VMs → guest prep on all
  (prep_node.sh direct / prep_tcm_node_scst.sh passthrough) → **cross-node
  caw_verify proof (aborts if faked CAW)** → fresh_cluster_mount CAW (no
  force_transport) → optional mkdir smoke storm + dmesg health. N default 2.
- Guest halves reused: `tools/prep_node.sh` (iscsiadm→192.168.120.1:3260,
  32-aware), `tools/prep_tcm_node_scst.sh` (SCST_FIO, sg_opcodes CAW, 180s
  timeout). Fan-out via tests/criteria/lib.sh fresh_cluster_mount + mxfs_sshpass.
- Doc: `docs/test_infra_scst_caw.md`. End-user doc: `docs/iscsi_setup.md`.

## NOT yet done
- Scripts NOT executed. Running scst_setup.sh TEARS DOWN the live 8/tcp LIO rig
  and enters the SCST-wedge-prone path (SCST_PROBLEM.md; 180s timeout mitigates,
  scst_unwedge recovers w/o reboot per RULE 2). Run when ready to move off TCP.
- lib.sh DEFAULT_NODES still lists only test1..16 (stale comment) — caw_cluster_up
  builds its own test1..testN list so it's not blocked, but worth fixing.

See [[doc-enduser-iscsi-caw-setup]], [[sess26-storage-infra-pernode-sessions]],
[[infra-lio-for-tcp-scst-for-caw-rationale]], [[test-cluster-scst-stack]].
