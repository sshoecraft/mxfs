---
name: ccloop-c7ee71c6-sess140-scst-fix-DEPLOYED-rig-rebuilt
description: sess140: SCST bvec-UAF fix (+caw-abort-reclaim.2) DEPLOYED to the live target; 32-node rig rebuilt healthy. Fence stack wedged by a double stack.sh u…
metadata:
  type: project
tags: [scst, deploy, rig, fence_inflight, wedge, infra]
---

# sess140 — the SCST fileio bvec-UAF fix is DEPLOYED

## What shipped

`+caw-abort-reclaim.2` is the RUNNING target stack now, not just a build.

    scst.ko        3.11.0-pre+caw-abort-reclaim.2  srcversion 4CACB719AB8EF3264AA4964
    scst_vdisk.ko  3.11.0-pre+caw-abort-reclaim.2  srcversion D621B132576AB508853B189
    iscsi-scst.ko  3.11.0-pre                      srcversion 1CE0B9BC17A1A2189964A61
    /sys/kernel/scst_tgt/version -> SCST version: 3.11.0-pre+caw-abort-reclaim.2

GOTCHA: scst.ko's srcversion is IDENTICAL across .1 and .2 — modpost hashes only
the .c sources listed in .<module>.mod, so a header-only change (the version
string in scst_const.h) does not move it. Use the `version:` field, not
`srcversion`, to tell .1 from .2 for scst.ko. Only scst_vdisk.ko's moved.

## Deployment recipe that worked (repeat verbatim)

1. 32 nodes parallel: `umount /mnt/shared; rmmod mxfs` — 32/32 clean.
2. 32 nodes parallel: `multipath -f mpatha; iscsiadm -m node -u; -o delete`.
   Target sessions 64 -> 0.
3. clyde: `echo 0 > .../enabled`, `del 0` to `luns/mgmt`, `del_target`,
   `del_device` for BOTH `mxfs` and `fencedelayf`.
4. `pkill iscsi-scstd` FIRST (it holds iscsi_scst at refcount 3, so rmmod fails
   otherwise), then `rmmod iscsi_scst scst_vdisk scst`.
5. `cd /src/scst/scst && sudo make install`; `cd /src/scst/iscsi-scst && make &&
   sudo make install`; `depmod -a`.
6. `scripts/scst_setup.sh setup` then `scripts/rig.sh mpath 32`.

Result: 32/32 nodes with 2-path /dev/mapper/mpatha (serial=2e476d07), 64
sessions, 0 active commands on every production session. Production is HEALTHY
on the fixed module and stayed healthy through everything below.

## Harness fix landed: the stack now records its own mode

`inflight_ab.sh:66` resolves devices with `eval "$(sudo bash stack.sh devmap)"`.
`sudo bash` DROPS the environment, so `MXFS_FENCE_MODE=fileio` never reached
devmap and a live fileio stack reported "stack not up" (it printed the blockio
dm name `/dev/mapper/mxfsfence`). Worse than a nuisance: an arm could silently
measure the wrong handler.

Fixed in `tests/fence_inflight/stack.sh`: `up` writes the mode to
`/var/lib/mxfs-fence/mode`, `MODE` resolves `${MXFS_FENCE_MODE:-<file>:-blockio}`,
`down` removes it. `inflight_ab.sh` precondition dump now uses `$TARGET` and
`$DM` from devmap instead of the hardcoded blockio names.

Verified: env-less `sudo bash stack.sh devmap` returns MODE=fileio,
TARGET=iqn.2026-08.mxfs.fence:inflightf, DM=/dev/mapper/mxfsfencef.

## DO NOT run `stack.sh up` twice — it reinstates the iSCSI sessions

This cost the session its first measurement. Running `up` on an already-up stack
re-issues `iscsiadm --login`, which REINSTATES both sessions (same ISID):

- old sda/sdb are removed and re-added as new host numbers (12/13),
- so the arm's `/dev/sdb` open returns ENXIO "No such device or address"
  mid-setup (it failed at "register survivor"),
- SCST is left with SIX sessions on the test target — victim, victim_1,
  victim_2, survivor, survivor_1, survivor_2 — which by itself breaks validity
  predicate #1 (exactly two target-observed I_T nexuses),
- `sd_remove` on the departing sda issues SYNCHRONIZE CACHE down the dying
  session. `stack.sh up` sets `replacement_timeout=300` AND
  `/sys/block/sdX/device/timeout=300`, so that command waits ~5 min per try.

Resulting wedge (all confined to the fence stack; production untouched):

    kworker/u113:15  D  blk_execute_rq <- scsi_execute_cmd <- sd_sync_cache
                          <- sd_shutdown <- sd_remove <- scsi_remove_target
    4x iscsi_conn_cleanup  D  msleep <- close_conn+0x6bf [iscsi_scst]

`fencedelayf` device `block` attribute reads "0 0" — this is NOT the
block_count wedge family (sess37/38, scripts/scst_block_diag.py). 3 commands
parked across victim/survivor/victim_2.

If it does not clear on its own, the supported lever is `force_close` in
`/sys/kernel/scst_tgt/targets/iscsi/<tgt>/sessions/<sess>/`.

## The stranded loop0 requests are NOT bvec-corrupted (but prove nothing yet)

`scripts/loop_unwedge/` act=0 on /dev/loop0:

    rq[0] tag=77  op=0 bytes=4096 segs=1 sector=67896  bv[0] pfn=0x14969d len=4096 off=0
    rq[1] tag=104 op=0 bytes=4096 segs=1 sector=67896  bv[0] pfn=0xddbf5b len=4096 off=0
    survey: 2 in-flight request(s), 2 bio(s), 0 request(s) with a freed/reused bvec chain

Zero corruption, and no GPF anywhere in this session's dmesg — contrast sess138
on `.1`, where 3 of 3 kmalloc'd arrays were corrupt.

BUT BE HONEST ABOUT THE SAMPLE: both are `segs=1`. Under the old bug a
<=4-segment command used the inline `p->async.small_bvec[4]` and was NEVER
corrupted (sess138's rq[3], 1 seg, was fully intact). So this observation is
entirely inside the class that was always clean. It is NOT evidence the fix
works. The fix still needs a run that puts >4-segment commands through the
fileio async path.

Also note loop0 has NOT been recreated since sess136 — `stack.sh up` reuses an
existing loop for the image — so these two strays may predate the fix entirely.

## Next steps

1. Clear the fence-stack wedge (wait out the SCSI timeout, else `force_close`
   the stale sessions), then `stack.sh down` and delete loop0 so the next
   stage-(ii) run starts on a loop device with no history.
2. Bring the fileio stack up EXACTLY ONCE, then run the ruled order
   0x04 -> 0x05 -> 0x04 with ARM_SEQ=1,2,3 (`inflight_ab.sh`, score with
   `verdict.py`). This is stage (ii) of D-PR-FENCE-PREEMPT-WITHOUT-ABORT's step
   4, its sole closure blocker.
3. Separately, verify the UAF fix on >4-segment traffic: the production 32-node
   rig is that workload, so a full 32/caw board on the fixed target doubles as
   the RULE-4 step-2b verification. Sample loop-free: check for GPFs and re-run
   the sess138 in-situ inspector against the production path if a wedge recurs.
