---
name: trap-dm-delay-under-a-pr-registering-mount-conflicts-with-its-own-register-because-iterate-devices-lists-the-path-three-times
description: TRAP (s147c/s57): a whole-LUN dm-delay map under an MXFS mount fails REGISTER on an unregistered nexus: dm_pr_register iterates dm-delay's read/write…
metadata:
  type: feedback
tags: [rig, dm, scsi-pr, harness, trap]
---

# dm-delay cannot sit under a mount that registers a SCSI PR key

## What happened (s147c, 2026-09-22, tests/evidence/20260922T044107Z_dlywrite_s147c)

`tests/delayed_write_across_fence.sh` remounted the victim through `/dev/mapper/mxfsdelay` (`0 SZ delay 8:0 0 0`). The mount died in the PR register:

- `P305-PR-SWAP-NOKEY REGISTER rk=X sark=X returned RESERVATION CONFLICT` (nexus does not hold X — true, the clean unmount had retired it)
- `P305-PR-NEXUS-ALREADY-REGISTERED plain REGISTER of key X returned RESERVATION CONFLICT` — on a nexus that `sg_persist -k` afterwards showed held NOTHING of test2's; only the peer's key was on the LUN.

## Why

The module's REGISTER goes through the stacked device's `pr_ops` (`pal/linux/kern.c mxfs_pal_scsi_pr_register` → `dm_pr_register`), not to the resolved backing sdev (`P-MPATH-RESOLVE` is for passthroughs). `dm_pr_register` (drivers/md/dm.c) calls `__dm_pr_register` for every device `iterate_devices` reports and rolls back on the first failure. dm-delay's `delay_iterate_devices` reports its read, write AND flush class devices — the SAME `dm_dev` three times for a 3-argument table. So: register #1 succeeds, register #2 conflicts (nexus now registered), `fail_early` → rollback unregisters the key → the caller sees CONFLICT and the LUN ends with the key removed. The module's diagnosis "predecessor key on this nexus" is then wrong, and the mount refuses.

The record and the harness header had claimed the module issues PR commands to the sdev directly. It does not for REGISTER; read `get_pr_ops` before assuming.

## What works instead

A single-path dm-multipath map created WITHOUT the `mpath-` uuid prefix (multipathd ignores it; `multipath -ll` stays empty):

    dmsetup create mxfsmp --table "0 $SZ multipath 1 queue_if_no_path 0 1 1 round-robin 0 1 1 8:0 1"
    dmsetup message mxfsmp 0 fail_path 8:0      # hold: every request requeued
    dmsetup message mxfsmp 0 reinstate_path 8:0 # release

Multipath lists the path once, which is the shape `dm_pr_register` was built for. Verified by hand on test2: a direct read through the failed path sat in `submit_bio_wait` (D state) 5.3 s until the reinstate; `/sys/block/dm-N/inflight` reads 0 0 for request-based dm (the request is on the blk-mq requeue list, `/sys/kernel/debug/block/dm-N/requeue_list`), so do not assert on inflight. `dmsetup remove` right after can report busy (udev); use `--retry`.

Cleanup trap: a lap that aborts after creating the map but before its destroy/restart cleanup must unmount and `dmsetup remove` the map itself, or the next prep fails with `/dev/sda already mounted or mount point busy` (s147d, s147e).
