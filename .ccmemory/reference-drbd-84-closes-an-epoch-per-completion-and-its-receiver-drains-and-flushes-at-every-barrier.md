---
name: reference-drbd-84-closes-an-epoch-per-completion-and-its-receiver-drains-and-flushes-at-every-barrier
description: DRBD 8.4: a write's completion closes the current epoch; with wo:f the receiver drains all peer writes + flushes per barrier. Bytes/epoch ≈ in-flight…
metadata:
  type: reference
---

Read from /src/linux/drivers/block/drbd (the in-kernel DRBD 8.4 that Proxmox 9 runs):

- `drbd_req.c:243-245` (drbd_req_complete): "Before we can signal completion to
  the upper layers, we may need to close the current transfer log epoch." When
  a completing write belongs to the current epoch, `start_new_tl_epoch()` runs.
  So an epoch holds roughly the writes that were in flight when the first of
  them completed: **bytes per epoch ≈ the submitter's in-flight window.**
- `drbd_req.c:880-881` (QUEUE_AS_DRBD_BARRIER): an empty flush from above, such
  as an XFS log write's PREFLUSH, also closes the epoch.
- `drbd_req.c:705-706`: an epoch also closes at `max-epoch-size` writes.
- `drbd_receiver.c:1602-1605` (receive_Barrier): with write ordering
  WO_BDEV_FLUSH or WO_DRAIN_IO (`/proc/drbd` shows `wo:f` / `wo:d`), the
  receiver thread waits for every active peer write to finish
  (`conn_wait_active_ee_empty`), then flushes the backing disk (`drbd_flush`),
  synchronously. It receives nothing else meanwhile.

**Consequence:** anything that keeps a DRBD writer's in-flight bytes small (a
write cap, a low queue depth, frequent log forces) makes the peer drain its
pipeline and flush its disk cache that often. On a disk whose cache flush is
expensive (old SATA SSDs with a volatile write cache, queue depth 1), throughput
then falls with the window, whatever the bandwidth. Measured raw on the physical
pair before MXFS's cap existed (scripts/drbd_write_latency_probe.sh): unbounded
48-52 MB/s, bounded per host to 4/8/16 MiB 35/31/36 MB/s.

`disk-flushes no` removes the flush, but it is safe only with a battery-backed
or power-loss-protected cache. dual-primary needs protocol C.
