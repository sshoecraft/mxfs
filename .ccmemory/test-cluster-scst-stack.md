---
name: test-cluster-scst-stack
description: MXFS test cluster topology + storage stack. test1-32 ALL available, NOT partitioned. Storage = LIO/tcm_loop single shared LUN (no iSCSI). SCST torn d…
metadata:
  type: project
---

# MXFS test cluster + storage stack (rewritten 2026-06-14)

> **MAJOR CHANGE 2026-06-14:** the SCST iSCSI stack described in older
> sessions was **torn down** and replaced with a **LIO/tcm_loop single shared
> LUN** (no iSCSI). The cluster is **no longer partitioned** — all of
> test1–test32 are available for this repo (/src/mxfs, v5). Prior guidance to
> "keep LIO disabled / kill it if you see LIO-ORG" is now **REVERSED**:
> LIO-ORG IS the intended stack.

## Cluster
- **test1–test32 are ALL available for /src/mxfs testing — NOT partitioned.**
  (Old test1-16=v5 / test17-32=.1 split is GONE per user directive 2026-06-14.
  Using all 32 does NOT mean test every change on many nodes — pick node count
  to fit the test; small N for iteration, larger only when scale is the point.)
- All 32 are libvirt VMs on host `clyde`, under **`qemu:///system` (root)** —
  drive with `virsh -c qemu:///system` (sudo if not in libvirt group). System
  scope is REQUIRED: host-device LUN passthrough is root-only and the tap is on
  host bridge `br0` (needs CAP_NET_ADMIN). Session-mode defs are useless.
- Resolve nodes via DHCP hostnames `testN` (and `testN.vm.localdomain`).
- Shared LUN inside every VM is `/dev/sda`; mount point `/mnt/shared`.
- NOTE: test2 was historically under-provisioned (2 vCPU/2GB vs 4/4GB) — verify
  before scale tests.
- Coordinator reaches nodes via `tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass <cmd>`
  (root login, sshpass). `/src` is NFS (192.168.1.4:/src) on every node, so
  `/src/mxfs/mxfs.ko` is cluster-visible — no per-node copy. Do NOT touch clyde
  NFS exports (see [[infra-src-is-qnap-nfs-do-not-touch-exports]]).

## Storage stack = LIO fileio + tcm_loop (LOCAL, no iSCSI)
- Backing file: `/home/steve/disk.img` (50G, fallocated, NOT sparse).
- `scripts/lio_tcm_setup.sh {setup|status|teardown}` builds it on clyde:
  `disk.img` → LIO **fileio** backstore `mxfs` (write-through,
  `emulate_write_cache=0`) → **tcm_loop** LUN0 → local `/dev/sdX` (vendor
  `LIO-ORG`, model `mxfs`). tcm_loop = in-kernel loopback SCSI fabric: NO
  iSCSI, no network, no initiator login. This DODGES the sess14-68
  iSCSI-loopback host-wedge class entirely (no iscsi_conn_cleanup kthreads).
- The setup maintains a stable symlink **`/dev/mxfs-shared` -> the live sdX**
  (the sdX letter and by-id WWN both change across teardown/re-setup, so VMs
  reference the symlink and never need re-editing). Re-run setup after any host
  reboot to re-point it.
- `scripts/wire_vms.sh {attach|detach|status} {N|node-list}` wires
  `/dev/mxfs-shared` into VMs as a shareable `device='lun'` SCSI passthrough on
  a virtio-scsi controller → guest `/dev/sda`. Edits PERSISTENT config
  (--config); running VM needs restart to apply. VALIDATED end-to-end on test1
  (guest sees `sda 50G LIO-ORG mxfs`).
- `scripts/define_vms.sh [N|node-list]` — **canonical VM (re)definition**: all
  nodes defined from ONE template → byte-for-byte identical hardware config
  (4 vCPU/4096MB, pc-i440fx-noble, virtio-scsi, shareable /dev/mxfs-shared at
  sda, virtio NIC on br0). Preserves each VM's MAC (DHCP testN resolution),
  UUID, boot-disk path; only those per-VM fields differ. Source of truth for VM
  config — edit the template + re-run to re-baseline. VERIFIED 2026-06-14: all
  32 normalize to one identical config. (define_vms already wires the LUN;
  wire_vms.sh is for ad-hoc re-wiring.)
- **Full doc: `docs/test_infra_lio_tcm.md`** (chain, scripts, bring-up sequence,
  caveats). Supersedes the old `docs/qemu_tcm_loop_setup.md` (LIO iblock).

## CAW vs TCP DLM on this stack
- **This LIO/tcm_loop stack does NOT do SCSI CAW reliably** (the historical
  reason the project moved to SCST). It is for testing the **TCP DLM** transport
  (`force_transport=1`), which needs no CAW/PR. For CAW testing, SCST is needed.
- Known TCP-DLM caveat: per-node throughput straggler at 3+ nodes was measured
  ~2.5mo ago (see [[tcp-dlm-straggler]] / "TCP DLM straggler issue"). That data
  is STALE and was a cross-time A/B — RE-MEASURE on this stack; the imbalance is
  in OUR TCP DLM code (infra held constant; CAW was balanced), not the infra.

## Per-node prep caveat (NEEDS UPDATE)
- `tools/prep_tcm_node_scst.sh` still keys on vendor **`SCST_FIO`** and runs a live
  `sg_compare_and_write` CAW check — BOTH wrong for this LIO/TCP-DLM stack
  (device is `LIO-ORG`/`mxfs`, no CAW). Must be updated (or superseded by the
  new harness) before it works against LIO/tcm_loop.
- KEEP the guest SCSI timeout widen: `echo 180 > /sys/block/sda/device/timeout`
  per node — prevents the 30s-timeout→ABORT_TASK→nexus-loss wedge under load
  (sess68), independent of transport.
