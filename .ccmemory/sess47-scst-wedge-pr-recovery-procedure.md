---
name: sess47-scst-wedge-pr-recovery-procedure
description: sess47: COMPLETE reusable recovery for the recurring SCST CAW↔READ atomic wedge + stale-PR block on mkfs (EBADE). Killing a phase run mid-test causes…
metadata:
  type: project
---

## sess47 (ccloop 14d31183) — full SCST/PR recovery, step by step (REUSABLE)

### What triggers it
Killing a `posix_phase_timing`/`run_tests` cluster run MID-TEST (TaskStop) leaves
remote orphans holding ilocks AND can crash VMs. This session: after killing a
phase run + virsh churn, **11 of 16 v5 VMs spontaneously shut off** (virsh
`shut off`), and destroying/force-closing sessions mid-I/O re-triggered the
sess43 SCST atomic wedge. LESSON: do NOT TaskStop a cluster run mid-test; let it
finish or fail naturally, THEN harvest dmesg (it persists).

### Symptoms
- `reset4.sh` → `mkfs failed on test1 (no MKFS_OK)`. Manual mkfs:
  `pwrite at offset 4096 failed: Invalid exchange` (EBADE = SCSI reservation conflict).
- `sg_persist --in --read-reservation /dev/sda` → held by a DEAD key (e.g.
  0xfd69d6d2, WE-RO type 5), ~11 stale registrants all same IQN diff ISIDs.
- `sg_persist --register-ignore` reports rc=0 + bumps PR generation but OUR key
  NEVER appears in read-keys → preempt no-ops. **Root: the SCST CAW↔READ atomic
  wedge blocks registration from sticking.** Host has `iscsi_conn_cleanup` threads
  in **D-state** (ps -eo stat,comm | grep iscsi_conn_cleanup) and zombie sessions
  that won't force_close.

### RECOVERY (the wedge MUST be cleared FIRST, then PR, then mkfs works)
1. Find deadlock edges (run as root; section addrs need sudo):
   `cd /src/mxfs`; TEXT/DATA/BSS/RODATA=`sudo cat /sys/module/scst/sections/.text` etc;
   `sudo gdb -q -batch -ex "set confirm off" -ex "add-symbol-file /lib/modules/$(uname -r)/extra/scst.ko $TEXT -s .data $DATA -s .bss $BSS -s .rodata $RODATA" -ex "core-file /proc/kcore" -x scripts/scst_atomic_edges.py`
   → prints each disk1 cmd: `op=0x88`(READ) / `op=0x89`(CAW), blockers=N, blocks[...].
2. Find the A↔B cycle: a READ (0x88) whose blocks[] contains a CAW (0x89) AND that
   CAW's blocks[] contains the READ. There were TWO CAWs sharing one READ — break
   each: `cd scripts/scst_unwedge; sudo insmod scst_unwedge.ko blocker=0x<READ> blocked=0x<CAW>; sudo rmmod scst_unwedge`.
   (blocker = the READ holding the edge; blocked = the CAW to requeue.) Re-run the
   edges script; repeat for each remaining cycle until the cmd list is EMPTY and
   no D-state iscsi_conn_cleanup. (scst_unwedge.ko already built in tree.)
3. PR clear: now that the wedge is gone, registration STICKS. From a live node
   (boot VMs first, restore `mount --bind /src/mxfs /mnt/mxfs-src` + `insmod /src/mxfs/mxfs.ko dirwr=1`):
   `RK=0xabcd1234; sg_persist --out --register-ignore --param-sark=$RK /dev/sda`
   (verify $RK now appears in `--read-keys`);
   `sg_persist --out --preempt-abort --param-rk=$RK --param-sark=<deadholder> --prout-type=5 /dev/sda`
   (reservation transfers to $RK); `sg_persist --out --clear --param-rk=$RK /dev/sda`
   → "NO reservation held", keys=1. Then `echo y | tools/mkfs_mxfs /dev/sda` → rc=0.
4. `bash tests/reset4.sh 16` → RESET_OK.

### pr_state / pr_file_name notes (what does NOT work)
- `echo ... > /sys/.../devices/disk1/pr_state` → rc=1 (needs device suspended).
- `echo path > pr_file_name` → "Device or resource busy" while ANY session/initiator
  is connected — can't use it for live clear. The sg_persist preempt path above is
  the one that works.

Related: [[sess43-scst-unwedge-and-p136]] [[sess46-barrier-timeout-and-lostupdate-same-root]] [[sess43-dirdata-pin-rootcause]]
