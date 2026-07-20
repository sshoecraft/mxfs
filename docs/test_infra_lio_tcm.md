# MXFS Test Infrastructure — LIO/tcm_loop shared LUN (current)

**Status:** current as of 2026-06-14. Supersedes the SCST iSCSI stack and the
older `docs/qemu_tcm_loop_setup.md` (LIO **iblock** + Samsung 870 runbook).

This is the host-side storage + VM wiring for the MXFS test cluster. It is built
entirely on `clyde` with **no iSCSI** — a local LIO fileio backstore exported
through LIO's loopback fabric (`tcm_loop`), passed into the VMs as a SCSI LUN.

## Why this stack
- **No iSCSI** → avoids the localhost-iSCSI-loopback host-wedge class that forced
  repeated host resets under the SCST stack (sess14–68: leaked
  `iscsi_conn_cleanup` kthreads, D-state `scst_vdisk` teardown). `tcm_loop` is an
  in-kernel SCSI fabric with no TCP, no portal, no initiator sessions.
- **fileio backstore** (not iblock): writes go through `pwrite()`; with
  `emulate_write_cache=0` there is no volatile per-host target cache. This is the
  backstore the sess36 diagnostic plan recommended over iblock.
- **Intended transport: TCP DLM.** This stack does NOT do SCSI CAW reliably, so
  it is for testing the TCP DLM transport (`force_transport=1`), which needs no
  CAW/PR. For CAW testing you need SCST instead.

## The chain
```
/home/steve/disk.img (50G, fallocated)
   → LIO fileio backstore "mxfs"  (write-through, emulate_write_cache=0)
   → tcm_loop LUN 0               (in-kernel loopback SCSI HBA)
   → host /dev/sdX                (vendor LIO-ORG, model "mxfs")
   → /dev/mxfs-shared             (stable symlink, re-pointed each setup)
   → VM <disk device='lun'> shareable on virtio-scsi
   → guest /dev/sda
```

**Why the `/dev/mxfs-shared` symlink:** the host `sdX` letter and the by-id WWN
both change across a teardown/re-setup (targetcli regenerates the backstore
UUID). VMs reference the fixed symlink so their definitions never need editing
when the host renumbers or the LIO stack is rebuilt. Re-run setup after any host
reboot to re-point it. (Guest-side the device is still `/dev/sda`.)

## Scripts (all in `scripts/`, RULE 3)

### `lio_tcm_setup.sh {setup|status|teardown}`
Host-side LIO/tcm_loop export.
- `setup` — load modules, create the fileio backstore over `disk.img`
  (write-through), create the tcm_loop target + LUN0, discover the resulting
  `/dev/sdX`, and (re)point `/dev/mxfs-shared` at it. Idempotent.
- `status` — show backstore, loopback target, and the host device.
- `teardown` — remove the loopback target + backstore and the symlink. Leaves
  `disk.img` intact.
- Env: `MXFS_LIO_IMG` (default `/home/steve/disk.img`), `MXFS_LIO_BSNAME`
  (default `mxfs`).

### `wire_vms.sh {attach|detach|status} {N|node-list}`
Attach/detach the shared LUN in VM definitions (persistent `--config`).
- `attach N` → test1..testN; `attach 2 7 18` → those nodes.
- Ensures a virtio-scsi controller, then attaches `/dev/mxfs-shared` as a
  shareable `device='lun'` at guest `sda`. Idempotent (detaches any existing
  `sda` first). A running VM needs a restart to apply.
- `status` shows each VM's shared-LUN source.

### `define_vms.sh [N|node-list]`
**Canonical VM (re)definition** — defines test VMs from ONE template so all
nodes are byte-for-byte identical in hardware config (4 vCPU / 4096 MB,
pc-i440fx-noble, virtio-scsi, shareable `/dev/mxfs-shared` at `sda`, virtio NIC
on br0). Preserves each VM's existing **MAC** (tied to DHCP `testN` resolution),
**UUID**, and **boot-disk path**; only those per-VM identity fields differ.
Destroys a running target first (test VMs are disposable). Never touches the
qcow2 boot image or the shared LUN data.
- `define_vms.sh` → all test1..test32; `define_vms.sh 4` / `define_vms.sh 2 7 18`.
- This is the source of truth for VM config — change the template here and
  re-run to re-baseline the fleet.

## Cluster facts
- **All of test1–test32 are available — the cluster is NOT partitioned.** (The
  old test1-16=v5 / test17-32=.1 split was removed 2026-06-14.) Using all 32
  does not mean test every change on many nodes; pick the node count to fit the
  test.
- VMs run under `qemu:///system` (root) — required for host-device LUN
  passthrough and br0 bridge attach.
- Shared LUN inside every VM: `/dev/sda`; mount point `/mnt/shared`.
- `/src` is NFS (`192.168.1.4:/src`) on every node — `mxfs.ko` is cluster-visible.
  Do NOT touch clyde NFS exports.

## Bring-up sequence
```bash
# 1. host storage (once per host boot)
scripts/lio_tcm_setup.sh setup          # disk.img -> /dev/mxfs-shared

# 2. VM definitions (once, or after template changes)
scripts/define_vms.sh                    # all 32 identical from template
# (define_vms already wires the shared LUN; wire_vms.sh is for ad-hoc re-wiring)

# 3. start the node count you need
for i in $(seq 1 N); do virsh -c qemu:///system start test$i; done
```

## Known caveats / TODO
- **`tools/prep_tcm_node_scst.sh` is SCST-only** — it keys on vendor `SCST_FIO`
  and runs a live CAW (`sg_compare_and_write`) check, both wrong for this stack
  (device is `LIO-ORG`/`mxfs`, no CAW). Needs a LIO/TCP-DLM equivalent (new
  harness). Keep the guest-side `echo 180 > /sys/block/sda/device/timeout`
  mitigation regardless (sess68 nexus-loss wedge prevention).
- **TCP DLM straggler:** ~2.5-month-old data showed a large per-node throughput
  spread on TCP DLM vs balanced CAW. That number is stale and was a cross-time
  A/B — RE-MEASURE on this stack. The imbalance is in our TCP DLM code (infra was
  held constant), not the infra.
- Before trusting the LUN with mxfs, run the cross-initiator coherency pre-flight
  (`scripts/sess36_e1_xinit_durability.sh` + the `e1b` concurrent variant).
