---
name: compiled-rig-prep-device-wiring-dmesg-sweep-and-forge-reservation-traps
description: Rig/harness traps: unwired platform sets and shared-LUN records, run.sh prep device defaults, cumulative dmesg sweep verdicts, raw forge vs SCSI rese…
metadata:
  type: feedback
tags: [compiled, rig, harness, prep, run.sh, dmesg, scsi-pr]
---

# Rig wiring and harness verdict traps: prep device identity, cumulative sweeps, raw LUN writes

Five traps with one shape: a harness or prep step reports a failure or a pass that comes from rig wiring or an evidence gap, not from the filesystem. Each is read as rig noise or a harness bug first, and none is ever a reason to widen a timeout or loosen a gate.

## Prep fails on device identity: the node or device is not wired for this rig

- **Platform sets made of rig VMs.** The `ubuntu2404` verification set lived on test5..test8 (moved there from test3/test4 after the same trap at 4 nodes). The first 8-node boards (`NODES=8 tests/board_4node_chain.sh ... tcp cawd`) died in 60 s with `PREP FAIL: bad nodes: test5(unmounted) ...` and `NODE_PREP_FAIL: device identity: ...:shared-lun-0 ... absent`. test5..8 held one iSCSI node record, for `plat-ubuntu2404`, and none for `:shared`. `prep_node.sh` refused, which is its job. `NODE_PREP_FAIL: device identity ... absent` is rig wiring, never a filesystem verdict, and `tools/criteria.py` classes it as rig noise. Fix: platform sets are VMs of their own, named `<platform>-N` and never `testN` (`ubuntu2404-1..8`, clones of test5); test5..8 got their platform record deleted, the `mxfs` package purged, and the `:shared` record (`node.startup = automatic`) created and logged in. Before the first board at a new node count, check each rig node has exactly one node record naming `:shared` (`iscsiadm -m node` on test1..testN). [[trap-a-platform-set-made-of-rig-vms-is-met-unwired-when-the-rig-grows-to-include-them]]
- **The `tcp` condition is wired to a rig that no longer exists on the multipath fleet.** `tcp` is run.sh condition 1 (TCP DLM over the LIO tcm_loop rig, LUN XML-wired into guests as `/dev/sda`); `caw` is condition 4 (dm-multipath, `/dev/mapper/mpatha`). On the multipath fleet `./run.sh 32 tcp prep_cluster` dies in prep_fs with `FS_PREP_FAIL: /dev/sda (sda) is claimed by: dm-1 ... This deployment condition's rig is not wired on this fleet`. The 32/tcp column's 20 PASS cells are from the older rig/build. To exercise TCP DLM on the current fleet: `MXFS_DEV=/dev/mapper/mpatha MXFS_CRIT=/src/mxfs/criteria.tcpmp.json ./run.sh 32 tcp prep_cluster`. `MXFS_CRIT` keeps results off the primary board, because cells are keyed `<N>/<dlm>` with no rig dimension and a different rig would silently overwrite the column in place. The force_transport gate in `d0286_tcp_wedge.sh` / `d0287_remaster_measure.sh` checks transport, not rig, so it is still satisfied. [[trap-32-tcp-condition-device-is-xml-sda-use-mxfs-dev-mpatha-and-mxfs-crit]]
- **Bare `run.sh prep_cluster` on the 2-node QNAP TCP rig.** `MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster` without `MXFS_NODE_LIST=test1,test2` and `MXFS_DEV=/dev/disk/by-path/ip-192.168.1.4:3260-iscsi-...-lun-0` picks the fleet default `/dev/sda` and fails in 13-20 s with the same `claimed by: dm-1` error, after it has already unmounted and unloaded the nodes. Every following harness then exits in 1 s with `INFRA: precondition not met (A='<id>' B=' ')`. Three rig steps were wasted. On this rig never call run.sh prep by hand; drive through `tests/sess511_chain_0756.sh <label> <steps>` (11 = held rejoin arm, 12 = delayed sameboot arm 1), which exports both variables. If a one-off prep is unavoidable, export the two first. [[trap-bare-run-sh-prep-on-the-qnap-2node-rig-needs-mxfs-dev-and-node-list-exported]]

Common lesson for all three: the `/dev/sda claimed by dm-1` and `device identity ... absent` strings mean the device or node binding is wrong for the rig under test. Check the condition's rig, the exported `MXFS_DEV`/`MXFS_NODE_LIST`, and the iSCSI records before reading anything into the failure.

## Sweep verdicts that count nothing as zero or count the previous run

`tests/tmpfile_churn_kill.sh` (tck) produced two consecutive false FAILs of the node_death_replay board row on 0.27.7 while the FS behaved correctly. Three compounding flaws, all fixed:

1. ssh-timeout counters summed as zero. A `timeout 60 $SSH` sweep that hit rc=124 wrote a bare header with no counters, and `sum()` treated the node as all zeros. A replayer whose ring provably held both victims' "foreign replay of slot N complete" lines gave frc=0 < victims=2, a false FAIL; the same gap can hide a real shutdown on an unreported node, a false PASS. Fix: command hoisted to `TCK_SWEEP_CMD`, one retry pass, then `SWEEP_MISSING` fails the lap closed. An evidence gap is a verdict, never a zero.
2. The `--no-prep` lap greps cumulative dmesg. `arm_prep` clears rings; lap 1 of the board row does not, so the recovery WAIT counted the previous run's replay-complete lines and released at +21 s, before heartbeat expiry (~62 s), unmounting the fleet mid-death-window. frc=0 was then legitimate (recovery never ran) but looked like a real no-replay defect. Fix: `dmesg -C` on every node at `--no-prep` lap start.
3. 36 separate full-ring greps per sweep against a 16 MB printk-flooded ring on a pegged 1-2 vCPU VM exceeded 60 s, which produced the rc=124s in (1). Fix: dump the ring once to `/tmp/tck_ring` and grep the file.

After all three the row passed (316 s / 470 s) with WAIT released at the genuine +77/+79 s and frc=2/2 on both laps.

Rules: any harness that sums per-node counters must fail closed on a missing per-node report; any cumulative-dmesg grep must be windowed by ring clear or marker. Other harnesses with the same shape are suspect across back-to-back runs: `d526_mass_unmount_verify`, `fr_mount_barrier_fail`, `rman_matrix`. Also: run.sh retains fail logs at `/tmp/run_<name>_<RUN_ID>`; the `logs: /tmp/tmp.*` path it prints is deleted at exit, so harvest the `run_*` copy. And `rman_matrix.sh`'s `$1` is the evidence dir, not an arm; `rman_matrix.sh base_shared base_shared base_shared` runs two arms with evidence in `./base_shared`. [[trap-a-cumulative-dmesg-sweep-produces-false-verdicts]]

## Raw LUN writes are refused unless the writer holds the reservation or nobody does

In `tests/authtail_mount_unwind.sh` lap s91b the survivor was unmounted first and the peer destroyed, and two seconds later the forge ran from the unmounted survivor: `SG_IO write failed: status=24 ...`. `status=%u` is decimal (`tools/recov_forge.c:338`), so 24 = 0x18 = RESERVATION CONFLICT, not the FUA problem named in the first output line (the FUA fallback had already fired and the retry was `fua=0`). The LUN is held WRITE EXCLUSIVE via SCSI PR; only the holder may write. A VM `destroy` kills the guest instantly but the appliance purges the key with the iSCSI session on its own, much longer schedule, so the destroyed peer still held the reservation. Reads are unaffected (`recov_forge dump` and `save` succeeded from the same node), which is what makes it confusing.

- Issue a raw LUN write from a node that is mounted and holds the reservation, or from a state where nobody holds it.
- `tests/d513_fswide_abort_preserves_death.sh` works from an unmounted survivor because it destroys the victim first; the still-mounted survivor fences and takes the reservation, and its own later unmount releases it. Copying its forge step into a harness with a different node order reproduces the failure.
- A cleanup write on the way out (restoring a forged slot) has the same problem and is worse: a terminal forged record left behind refuses every later mount including the next prep. Give it a bounded retry that outlasts the appliance's purge delay, and report tries and wall so a slow purge is visible.

[[trap-a-raw-forge-write-to-the-shared-lun-is-refused-while-another-initiator-holds-the-reservation]]
