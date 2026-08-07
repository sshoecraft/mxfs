---
name: ccloop-c7ee71c6-sess141-fence-stage-ii-blocker-ROOT-CAUSED-leaked-i_dio_count
description: sess141 ROOT CAUSE, measured: fence stage-(ii) wedges because the loop BACKING FILE inode has a leaked i_dio_count=1 from the sess136 GPF. Fix: fresh…
metadata:
  type: project
tags: [fence, loop, dio, scst, D-PR-FENCE-PREEMPT-WITHOUT-ABORT, sess141, rule4]
---

# sess141 — why fence stage (ii) has never run: a leaked `i_dio_count`

## The measurement (not a hypothesis)

`scripts/inode_dio_probe/` (new this session; same Makefile pattern as
`scripts/loop_unwedge/`):

    sudo insmod inode_dio_probe.ko path=/var/lib/mxfs-fence/fio-backing.img

    inode_dio_probe: /var/lib/mxfs-fence/fio-backing.img ino=62527935 dev=259:2
        size=2147483648 i_dio_count=1 i_count=1 i_writecount=1
    inode_dio_probe: ... i_rwsem locked=1 contended=1  VERDICT: i_dio_count LEAKED

Control, same instant, same probe: `/src/mxfs/CLAUDE.md` -> `i_dio_count=0`,
`i_rwsem locked=0`. And `/sys/block/nvme0n1/inflight` = `0 0`, so the 1 is not
a DIO legitimately in flight — nothing is in flight anywhere.

## The mechanism

`i_dio_count` is raised by `inode_dio_begin()` at the head of every
`iomap_dio_rw()` and dropped by `inode_dio_end()` at completion. sess136/137's
general protection fault in `dma_direct_map_sg()` killed the loop worker
INSIDE `__iomap_dio_rw()` on this file. `make_task_dead()` does not run the
matching `inode_dio_end()`. The count is stuck at 1 for the lifetime of the
in-core inode.

`ext4_dio_write_checks()` calls `inode_dio_wait(inode)` on the exclusive path
(extending / non-overwrite / unaligned-into-unwritten). That is
`wait_var_event(&inode->i_dio_count, ...)` — with a leaked count it never
returns.

## Observed signature and why it is diagnostic

- `dd iflag=direct` READ of /dev/loop0: **OK** — `ext4_dio_read_iter` takes
  i_rwsem shared and never calls `inode_dio_wait`.
- `dd oflag=direct` WRITE of /dev/loop0: **hangs forever** — exclusive path.
- blk-mq FLUSH to loop0: **hangs** — but only as a *consequence*.
  `loop_process_work()` drains its worker's `cmd_list` SERIALLY, so one hung
  `loop_handle_cmd` blocks every later cmd on that same worker.
- Reads kept working while flushes hung because the worker is chosen by the
  bio's blkcg css: `loop_queue_rq()` does `if (rq->bio) cmd->blkcg_css =
  bio_blkcg_css(rq->bio)`, and the blk-mq flush request (`fq->flush_rq`) has
  `rq->bio == NULL` -> `lo->rootcg_work`, a DIFFERENT cmd_list from a
  cgroup-tagged read. Two lists, two fates.

Stuck-worker stack (the whole diagnosis in one dump):

    ext4_dio_write_checks+0x127 / ext4_dio_write_iter / ext4_file_write_iter
    lo_rw_aio / do_req_filebacked / loop_process_work / loop_workfn

## Why it survived ~5 sessions

`tests/fence_inflight/stack.sh down` deliberately KEEPS the image
("torn down (image /var/lib/mxfs-fence/fio-backing.img kept)"). Every fileio
`up` since sess136 re-attached the SAME poisoned inode. Detaching the loop
device does not help; neither does a fresh loop device number. Only a NEW
INODE clears it.

## Hypotheses tested and REFUTED along the way (do not re-run these)

- H1 "loop0's `lo->rootcg_work` is poisoned because a worker died inside it,
  so `find_worker_executing_work()` re-queues onto the dead worker forever."
  REFUTED: loop0 with a fresh 1 MiB backing file flushed in ~4 ms.
  `tests/fence_inflight/loop_flush_probe.sh` (new) is the reusable control:
  loop1/loop2 -> `FLUSH_OK 4ms`.
- "root ext4 / nvme is sick." REFUTED: nvme inflight 0 0, Dirty 772 kB,
  no EXT4 errors on the root device.
- "a leaked exclusive i_rwsem." REFUTED by construction: O_DIRECT reads of the
  same loop device succeed, and a read takes i_rwsem shared.

## What the next session must do

1. Do NOT reuse `/var/lib/mxfs-fence/fio-backing.img`. Give `stack.sh` a fresh
   image path (fresh inode) for fileio mode, and add a `purge` that deletes it.
2. Do NOT `losetup -d /dev/loop0` and do NOT delete the old image while the
   stuck worker exists: it sleeps in `wait_var_event(&inode->i_dio_count)`, so
   freeing that inode would be a use-after-free. Leave loop0 + dm-0
   (`mxfsfencef`) + the parked `kworker/...+loop0` in place; they hold nothing
   production needs. `losetup --find` will skip loop0 automatically.
3. Add the flush probe as a precondition gate in `stack.sh up`.

## Host state left behind (harmless, documented)

loop0 attached to the poisoned image, dm-0 `mxfsfencef` present, one kworker
parked in `inode_dio_wait` forever, and (unless cleared) two `mount` processes
plus one `dd` in D on loop0. Production is untouched: 32 VMs up, 64 SCST
sessions on `iqn.2026-05.local.mxfs:shared`, target
`3.11.0-pre+caw-abort-reclaim.2`.
