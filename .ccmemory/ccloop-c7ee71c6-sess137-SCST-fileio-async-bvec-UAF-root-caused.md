---
name: ccloop-c7ee71c6-sess137-SCST-fileio-async-bvec-UAF-root-caused
description: sess137 ROOT CAUSE of the stage-(ii) fileio wedge: SCST fileio_exec_async() kfree()s the in-flight bvec at -EIOCBQUEUED - a UAF that GPF'd the loop0…
metadata:
  type: project
tags: [scst, vdisk_fileio, use-after-free, loop, dm-delay, D-PR-FENCE-PREEMPT-WITHOUT-ABORT, stage-ii, infra]
---

# sess137 — the stage-(ii) fileio LUN wedge is an SCST use-after-free, ROOT CAUSED

Not a timeout, not slowness, not "the dm-delay/loop sandwich is too deep".
**A kernel general protection fault killed the loop0 worker mid-submission and
leaked its in-flight requests.** Everything above it (SCST commands stuck in
EXEC_WAIT, deferred ABORTs, D-state `iscsi_conn_cleanup` msleep loops, the
`sd_sync_cache` unbind hang) is downstream of that one crash.

sess136 stopped one measurement short of this: it proved the layers *below* were
healthy and inferred "the stall is in or above the fileio handler". Correct, but
the discriminator it planned (point fileio at a file on the root fs) was NOT the
next step — the next step was reading dmesg for the window, where the oops sits.

## The measurement chain (all direct, none inferred)

1. `/sys/kernel/debug/block/loop0/hctx0/busy` → exactly **4 READ requests
   `.state=in_flight`** (tags 7/8/9/60). `dm-0 inflight=4`, `loop0 inflight=4`,
   **`nvme0n1 inflight=0`** — so they never reached the hardware.
2. Every layer is healthy *now*: aligned O_DIRECT reads of `/dev/loop0`,
   `/dev/mapper/mxfsfencef` and `disk.img` through the ext4 all return in ~13 ms.
   Only those 4 are leaked. Not a stalled stack — a leak.
3. `dmesg` at the instant the LUN came up (Aug 4 18:02:24):

```
general protection fault, probably for non-canonical address 0xdb9078b3a872313c
CPU: 12 PID: 1644142 Comm: kworker/u113:0
Workqueue: loop0 loop_rootcg_workfn
RIP: dma_direct_map_sg+0xa3/0x140     RBX=3 (sg index)  R12=6 (nents)  RSI=<garbage page ptr>
 __dma_map_sg_attrs -> dma_map_sgtable -> nvme_map_data -> nvme_prep_rq -> nvme_queue_rqs
 -> blk_mq_flush_plug_list -> __blk_flush_plug -> blk_finish_plug
 -> __iomap_dio_rw -> iomap_dio_rw -> ext4_file_read_iter
 -> lo_rw_aio -> do_req_filebacked -> loop_process_work -> loop_rootcg_workfn
```

The loop0 worker dereferenced a garbage `struct page *` at sg entry **3 of 6**
and died, stranding its 4 requests. blk-mq cannot recover them: loop's
`blk_mq_ops` has no `.timeout`, so `blk_mq_rq_timed_out()` just does
BLK_EH_RESET_TIMER forever.

## The defect (SCST, `scst/src/dev_handlers/scst_vdisk.c`)

`fileio_exec_async()` (~line 3158) — `vdisk_alloc_async_bvec()` (3060) uses the
inline `p->async.small_bvec[4]` when the command has <=4 buffer segments, else
`kmalloc_objs()`. Then, after submitting:

```c
iov_iter_bvec(&iter, dir, p->async.bvec, sg_cnt, total);
*iocb = (struct kiocb){ .ki_pos=p->loff, .ki_filp=fd, .ki_complete=fileio_async_complete };
if (o_direct) iocb->ki_flags |= IOCB_DIRECT | IOCB_NOWAIT;
for (;;) { ret = call_read_iter/call_write_iter(fd, iocb, &iter); ... }
if (p->async.bvec != p->async.small_bvec)
        kfree(p->async.bvec);          /* line 3230-3231 — UNCONDITIONAL */
if (ret != -EIOCBQUEUED) fileio_async_complete(iocb, ret);
```

Kernel contract (`/src/linux/block/bio.c`) — the array is **referenced, not copied**:

```c
int bio_iov_iter_get_pages(...) { if (iov_iter_is_bvec(iter)) { bio_iov_bvec_set(bio, iter); ... } }
void bio_iov_bvec_set(struct bio *bio, const struct iov_iter *iter) {
        bio->bi_io_vec = (struct bio_vec *)iter->bvec;   /* line 1181 */
        bio_set_flag(bio, BIO_CLONED);
}
```

So on `-EIOCBQUEUED` SCST frees an array the in-flight bio still points at.
**More than 4 bvec entries** is the trigger (GPT correction: not exactly
">16 KiB" — coalescing/compound pages/SG shape can move that boundary).

## Why it crashes on the loop stack but not on production

Plain ext4-on-nvme: `__iomap_dio_rw` submits and `blk_finish_plug` runs
`nvme_queue_rqs` (→ `blk_rq_map_sg` → `dma_map_sg`) **before returning**
-EIOCBQUEUED, so the DMA mapping reads the bvec while still allocated. Insert
dm-delay + loop and the real submission is deferred to the loop workqueue: the
free happens first, the slab is recycled, nvme maps garbage.

## PRODUCTION IS ON THE SAME PATH — contamination is real

`/sys/kernel/scst_tgt/devices/mxfs`: `vdisk_fileio`, `filename=/home/steve/disk.img`,
**`async=1 o_direct=1`**, blocksize=512, nv_cache=0, write_through=0. Same code.
Every transfer with >4 segments has been freeing an in-flight bvec, and
`blk_update_request`/`bio_advance_iter` walk `bi_io_vec` at completion — i.e.
*after* the free — even on the plain stack.

GPT RULE-5 ruling on contamination (gpt-5.6-sol): **"Treat previous unexplained
production anomalies as plausibly contaminated by this bug... a real
data-integrity and kernel-memory-safety defect, not merely a loop-only crash
bug."** Its evidence standard:
- timing/perf evidence — SUSPECT if the command could have >4 bvecs (hangs, tail
  latency, abort storms, completion anomalies are directly contaminated);
- error-rate evidence — SUSPECT (the defect manufactures errors/hangs unrelated
  to media or controller health);
- data-integrity evidence — not automatically invalid, but no unexplained
  mismatch may be attributed to MXFS/ext4/nvme without retesting after the fix;
- negative evidence — a clean run does NOT establish absence (freed slab often
  still holds the old contents);
- runs whose commands stayed <=4 bvecs — unaffected.
- "For a 32-node clustered-filesystem qualification run, I would not consider
  unexplained historical anomalies clean evidence against the cluster
  filesystem. Rebaseline after patching."

Realistic failure mode on the plain stack, ranked: completion-accounting damage
(invalid bvec lengths, OOB traversal, bogus residual, hung or prematurely
completed commands, WARN/oops) is MORE likely than cleanly wrong data; but
silent corruption cannot be excluded, because the "mapping always finishes under
blk_finish_plug" assumption breaks under requeue/quiesce/NVMe resource shortage/
controller recovery/merge/split.

## The ruled fix (not just the minimal patch)

1. Move ownership of the heap bvec to terminal completion — free at the top of
   `fileio_async_complete()`, then `p->async.bvec = p->async.small_bvec`.
   `kfree()` in IRQ/softirq/end-I/O context is safe (allocation gfp does not
   carry over). iomap guarantees `ki_complete` fires only after the LAST bio of a
   split DIO, so completion IS the correct boundary.
   - CAVEAT to audit: the `do_verify` early-return path in
     `fileio_async_complete` — freeing at the top is right ONLY if that path does
     not re-submit using this bvec. Also route every failure exit between
     allocation and `call_*_iter()` through the same helper.
   - Do NOT free on abort/teardown unless the underlying file I/O actually
     completed or was synchronously cancelled: a never-called completion must
     leak, not double-free. Audit SCST abort, forced cmd destruction, LUN
     removal, backing-file close, module unload, session teardown.
2. **Reinitialize `iov_iter` AND the kiocb on every retry** of the
   -EAGAIN/-EOPNOTSUPP loop, rather than reusing a possibly-advanced iter.
3. **Stop hand-building the kiocb.** Use `init_sync_kiocb(iocb, fd)` then set
   `ki_pos`, `ki_complete`, `IOCB_WRITE` for writes, `IOCB_DIRECT|IOCB_NOWAIT`
   for o_direct. The zeroed compound literal drops file-derived flags
   (IOCB_DSYNC/SYNC/APPEND), IOCB_WRITE, ioprio, and any future field. Decide
   O_APPEND (should be rejected/cleared for a LUN) and O_SYNC/O_DSYNC
   intentionally.
4. Never retry after a positive short result.
5. Reproduce under KASAN/SLUB poisoning if a test kernel is available; test BOTH
   loop/dm-delay (wide window) and plain ext4/NVMe under queue pressure.
6. Drain/quiesce LUNs before module reload; never unload with outstanding queued
   file I/O.

## Rig state left by sess137

- Production `iqn.2026-05.local.mxfs:shared` — **64 sessions, untouched, healthy**.
- Test target `iqn.2026-08.mxfs.fence:inflightf` — 6 stale SCST sessions, 4
  leaked loop0 requests, 5 D-state tasks. **Do NOT `del_device fencedelayf`** —
  `scst_wait_for_tgt_devs` is an unbounded msleep and will wedge `scst_uid` and
  all SCST management (see compiled-scst-iscsi-infra-wedge-recovery).
- RULE 2 honoured: clyde not rebooted, no reboot proposed.

## Next steps (in order)

1. Write `scripts/loop_unwedge/` — a module that takes the loop device's
   major:minor, gets `bdev_open_by_dev()` → `bdev->bd_disk->queue->tag_set`, and
   uses `blk_mq_tagset_busy_iter()` + `blk_mq_end_request(rq, BLK_STS_IOERR)` to
   force-complete the leaked requests. All symbols VERIFIED exported on
   6.8.0-101: `bdev_open_by_dev`, `bdev_open_by_path`, `bdev_release`,
   `blk_mq_tagset_busy_iter`, `blk_mq_end_request`, `blk_mq_quiesce_queue`,
   `blk_mq_unquiesce_queue`. `struct request_queue.tag_set` is at
   `include/linux/blkdev.h:523`; `struct bdev_handle`/`bdev_open_by_dev` at
   :1502-1515. Model it on the existing `scripts/scst_unwedge/` (same Makefile
   shape). Erroring the 4 requests unwinds dm-delay endio → ext4 DIO endio →
   `fileio_async_complete` → SCSI commands complete → aborts drain →
   `close_conn` threads exit → sessions clean up.
2. Patch `/src/scst` per the ruled fix; `cd /src/scst/scst && make && sudo make
   install`. Provenance CONFIRMED: installed
   `/lib/modules/6.8.0-101-generic/extra/{scst.ko,dev_handlers/scst_vdisk.ko}`
   are byte-identical in size to `/src/scst/scst/src/...` and report
   `3.11.0-pre+caw-abort-reclaim.1` (suffix at
   `scst/include/scst_const.h:61`). Bump that suffix for the new build so the
   running module is identifiable.
3. Reloading SCST is NOT a host reboot (RULE 2 permits it) but drops the 32-node
   LUN — destroy the VMs first (they are disposable), then reload, then rebuild
   the rig.
4. Then resume stage (ii): the loop stack is the RIGHT rig, and it is now a
   *sharper* one — it is the configuration that makes this class of UAF
   deterministic.
