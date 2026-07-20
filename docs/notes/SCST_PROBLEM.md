# SCST problem statement — for the dedicated SCST session

Target to fix: **SCST 3.11.0-pre** (installed modules at
`/lib/modules/6.8.0-101-generic/extra/{scst.ko,iscsi-scst.ko,dev_handlers/scst_vdisk.ko}`).
This is the iSCSI target serving the MXFS test cluster on host **clyde**.

## How the rig is wired (context)

- clyde runs SCST with the `vdisk_fileio` handler exporting ONE shared backing
  device **disk1 = `/home/steve/disk-1.img`** (20G), `write_through 1`,
  `nv_cache 0`. Config: `/etc/scst.conf`.
- That one device is published through 16 iSCSI targets
  (`iqn.2026-05.local.mxfs:disk1`, `:disk1n2` … `:disk1n16`), each mapping
  **LUN 0 → the same disk1 device**.
- **clyde is also the iSCSI initiator**: it logs into its own target 16 times
  (one session per target = one I_T nexus per VM), and hands each resulting
  `/dev/disk/by-path/...-lun-0` block device to a test VM via QEMU SCSI-LUN
  passthrough (`<disk device='lun' bus='scsi'>`). So each guest's `/dev/sda`
  is a real SCSI device with PR + CAW passing through to SCST.
- SCSI Persistent Reservations are **per-I_T-nexus**; each of the 16 host
  sessions is one PR registrant. The cluster uses **type 5 PR
  (WRITE EXCLUSIVE — REGISTRANTS ONLY)**: any registered nexus may write; an
  unregistered nexus's WRITE returns SCSI **RESERVATION CONFLICT (0x18)**.

## The workload that triggers it

16 nodes concurrently run a shared-directory `mkdir` storm against one mxfs
filesystem on the shared LUN. MXFS coordinates with **SCSI COMPARE AND WRITE
(CAW, opcode 0x89)** locks, and `mkfs` zeroes its slot table with **WRITE SAME**.
So the LUN sees heavy concurrent CAW plus periodic WRITE SAME.

## The bug (three linked defects, root first)

### 1. Stuck `iscsi_conn_cleanup` / `close_conn` kthread leak → PERMANENT device wedge
SCST executes CAW (0x89) and WRITE SAME as **strictly-serialized** commands:
block the device, wait for all outstanding commands to drain, execute, unblock.
Under the concurrent CAW storm:

1. A strictly-serialized command waits to drain longer than the initiator's 60s
   command timeout → guest SCSI EH issues **ABORT_TASK**.
2. The abort can't complete because the command is parked in
   **`EXEC_CHECK_BLOCKING`** (behind the device-block). SCST logs
   "deferring ABORT". EH escalates → **LUN_RESET → NEXUS_LOSS → connection drop**.
3. **Each dropped connection spawns an `iscsi_conn_cleanup` kthread that gets
   stuck FOREVER in the `close_conn` `msleep` loop (D-state).** Observed 33–49
   accumulated. They hold command refcounts, so the device's outstanding-command
   count **never drains again**.
4. From then on **every** strictly-serialized command (any CAW, the next
   `mkfs` WRITE SAME) blocks forever in `EXEC_CHECK_BLOCKING` **even on an
   otherwise-idle LUN**. The device is permanently wedged.
5. `systemctl stop scst` hangs "deactivating" (`scst_uid` work thread stuck in
   `scst_acg_del_lun` msleep); module unload is impossible (D kthreads). Today
   the only recovery is `scripts/scst_unwedge/` (a kmod that breaks the block
   edge) or a host reboot.

**Fix needed:** when a connection drops mid-EH with commands parked in
`EXEC_CHECK_BLOCKING`, `close_conn`/`iscsi_conn_cleanup` must be able to
force-abort / reclaim those commands so refcounts drain and the thread can
exit. The transient timeout must not become a permanent device wedge.

### 2. CAW ↔ READ atomic blocking DEADLOCK (same LBA)
On overlapping LBAs, a CAW (0x89) and a READ (0x28) end up **mutually blocked**:
`CAW.blocked_arr[0] == READ#1` and `READ#1.blocked_arr == [CAW]` — a clean A↔B
cycle that never resolves (proven via `scripts/scst_atomic_wedge_diag.py`
walking `vdev_list`). This is a deadlock in SCST's command-blocking/serialization
ordering for atomic ops vs reads to the same range.

**Fix needed:** the blocking/serialization order for atomic (CAW/WRITE SAME)
vs overlapping reads must be acyclic — a CAW and a READ to the same LBA must not
be able to each wait on the other.

### 3. Strictly-serialized CAW/WRITE-SAME drain exceeds the initiator timeout
Even without the leak, the "block device + drain all outstanding + exec" model
makes a single CAW (which only touches a small LBA range) wait behind the entire
device's in-flight queue. Under 16-way concurrency that drain wait exceeds the
60s initiator timeout, which is what kicks off defect #1.

**Fix needed (mitigation / root):** reduce the serialization scope (don't block
and drain the whole device for an atomic op that only touches one region), or
otherwise bound the drain so it can't exceed the initiator command timeout.

## Downstream symptom on the MXFS / guest side (so you can confirm a fix)

- NEXUS_LOSS drops that nexus's PR registration → its subsequent WRITEs return
  **RESERVATION CONFLICT**. Guest dmesg: `reservation conflict` →
  `XFS log I/O error -52` → `Filesystem has been shut down (log error 0x2)`.
  Because the LUN is shared, one node's shutdown loses the whole iteration
  (1600 dirs in the canonical `zero_silent_loss` run).
- Host-side detection: `ps -eo stat,comm | awk '$1 ~ /^D/'` shows
  `iscsi_conn_cleanup` in D-state; `dmesg | grep EXEC_CHECK_BLOCKING` on clyde.

## Existing diagnostics already in the MXFS tree (reuse these)

- `scripts/scst_atomic_wedge_diag.py` — gdb script: walks `vdev_list`, prints
  blocked commands and the A↔B cycle. (gdb invocation + section-address recipe
  is documented in memory `sess51-scst-caw-read-wedge-full-recovery-proven`.)
- `scripts/scst_unwedge/` — kmod that removes a specific block edge to recover a
  live wedge without rebooting (workaround, not a fix).
- `scripts/scst_block_diag.py`, `scripts/scst_mon.py`,
  `scripts/scst_atomic_edges.py` — additional wedge/atomic-op diagnostics.

## Reproducer

From the MXFS repo on clyde, against a healthy SCST target + 16 booted VMs:
`bash tests/criteria/zero_silent_loss.sh --iters 3 --dpn 100 --mode 1`
(or the lower-level `scripts/sess88_workload_a_modeN_baseline.sh
/src/mxfs/mxfs.ko 100 1 1`). The wedge appears within one iteration of the
16-node CAW storm.

## What a fixed SCST looks like

The 16-node CAW storm runs to completion with no `iscsi_conn_cleanup` D-state
threads, no `EXEC_CHECK_BLOCKING` permanent blocks, no reservation conflicts,
and `mkfs` WRITE SAME never starves on an idle device. At that point the MXFS
`zero_silent_loss` criterion can be evaluated on CAW (the ship transport)
instead of being masked by infra wedges.
