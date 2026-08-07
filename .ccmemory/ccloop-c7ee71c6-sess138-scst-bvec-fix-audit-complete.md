---
name: ccloop-c7ee71c6-sess138-scst-bvec-fix-audit-complete
description: sess138: rig UNWEDGED via new scripts/loop_unwedge; all GPT-required audits for the SCST bvec-UAF fix discharged — patch is ready to write.
metadata:
  type: project
tags: [scst, vdisk_fileio, use-after-free, loop_unwedge, infra, next-step]
---

# sess138 — rig unwedged, and every audit the fix was blocked on is discharged

## 1. THE RIG IS UNWEDGED (no host reboot; RULE 2 honoured)

`scripts/loop_unwedge/` (new, builds clean on 6.8.0-101) force-completed the
four leaked loop0 requests. Result, measured:

- D-state tasks **5 -> 0** (the `sd_sync_cache` kworker and 4 `iscsi_conn_cleanup`)
- test target `iqn.2026-08.mxfs.fence:inflightf` sessions **6 -> 0**
- `loop0` / `dm-0` / `nvme0n1` inflight all **0**
- production `iqn.2026-05.local.mxfs:shared` **64 sessions, untouched**

Usage (survey is always safe and always runs first):

    cd scripts/loop_unwedge && make
    sudo insmod loop_unwedge.ko devpath=/dev/loop0            # inspect
    sudo rmmod loop_unwedge
    sudo insmod loop_unwedge.ko devpath=/dev/loop0 act=1 expect=4
    sudo rmmod loop_unwedge

`expect=N` refuses to act unless exactly N in-flight requests are found.
It works on ANY blk-mq queue whose driver died holding requests, not just loop.

## 2. Audits GPT required before moving the kfree — ALL DISCHARGED

- **`do_verify` early return** (`fileio_async_complete` line 3141-3153):
  SAFE to free at the top. `scst_do_verify_work()` (line 3025) uses only
  `w->cmd`, calls `vdev_verify(cmd, loff)` which runs its own I/O, and never
  reads `p->async.bvec`. Also unreachable on error: the branch is `else if`
  after two `ret < 0` arms.
- **Teardown / never-completing paths**: `vdisk_on_free_cmd_params()` (line
  3260) frees ONLY `p->sync.kvec`, and only `if (!p->execute_async)`. The async
  bvec is never freed there. So a completion that never fires LEAKS the array
  rather than double-freeing it — exactly the behaviour GPT demanded. **No
  change to `vdisk_on_free_cmd_params` is needed or wanted.**
- **`p` outlives the I/O**: `p` is freed in `fileio_on_free_cmd()` (line 3268)
  via `kmem_cache_free(vdisk_cmd_param_cachep, p)`, driven by SCST freeing the
  cmd — i.e. after `scst_cmd_done()`. `fileio_async_complete` reaching `p` by
  `container_of(iocb, ..., async.iocb)` is sound.
- **No other reader/freer of the array**: `grep -n "async\.bvec\|small_bvec"`
  returns only lines 267, 3070-3076, 3190, 3205/3207, 3230-3231. The kfree at
  3230-3231 is the only one.
- **Only one exit between alloc and submit**: `vdisk_alloc_async_bvec()` failure
  returns before `p->execute_async = true`, and there is no other early return
  before `call_*_iter()`. Nothing to reroute.

## 3. The patch to write (scst_vdisk.c, all line numbers current)

1. **Delete lines 3230-3231.** Free at the TOP of `fileio_async_complete()`
   (line 3128), then `p->async.bvec = p->async.small_bvec;` so it is idempotent:
   `if (p->async.bvec != p->async.small_bvec) { kfree(p->async.bvec); p->async.bvec = p->async.small_bvec; }`
   `kfree()` in IRQ/softirq is fine. Note this runs on BOTH completion routes
   (fs-called on `-EIOCBQUEUED`, synchronously called at line 3232-3239
   otherwise), so it is exactly-once.
2. **Reinit `iov_iter` AND the kiocb inside the retry loop** (3218-3229). Today
   `iov_iter_bvec()` (3205) and the kiocb init (3209) sit OUTSIDE the loop, so a
   retry after `-EAGAIN` reuses a possibly-advanced iter and an advanced
   `ki_pos`. Move both inside, or re-run them at the top of each attempt.
3. **Replace the hand-built kiocb** at 3209-3213 with `init_sync_kiocb(iocb, fd)`
   then set `ki_pos`/`ki_complete` (and `IOCB_WRITE` for writes). In 6.8
   `init_sync_kiocb` sets `ki_flags = filp->f_iocb_flags` + `ki_ioprio`; the
   current zeroed compound literal drops IOCB_DSYNC/SYNC/APPEND, ioprio and any
   future field. Clear IOCB_APPEND defensively — a LUN must never append.
4. Already correct, do not "fix": the loop breaks on `ret >= 0`, so there is no
   retry after a positive short result (GPT item 4).

## 4. Remaining sequence after the patch

Bump the `caw-abort-reclaim.1` suffix in `scst/include/scst_const.h:61` so the
running module is identifiable, `cd /src/scst/scst && make && sudo make install`.
Reloading SCST drops the 32-node LUN, so destroy the VMs first (disposable),
reload, rebuild the rig, then rebaseline — per the sess137 GPT ruling, prior
unexplained anomalies are contaminated evidence and a clean run does not
establish absence.
