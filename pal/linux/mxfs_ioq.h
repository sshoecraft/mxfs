/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * mxfs_ioq.h — the bound on the writes one mount has in flight on a DRBD
 * attachment (pal/linux/drbd.c).  Kernel only: callers hand it bios.
 *
 * WHY.  On DRBD every MXFS coordination write (a bakery register, the heartbeat
 * compare-and-swap) is an ordinary write on the same device as the guests'
 * data, and DRBD carries them in one ordered stream to a peer that writes them
 * to a disk shared with its own guests.  Nothing can lift a coordination write
 * past data queued ahead of it: DRBD's protocol carries no priority, and its
 * receiver submits every replicated write alike.  So the depth of the queues in
 * front of it — the local disk's, DRBD's, the link's and the peer disk's — is
 * set by how much data both nodes have in flight, and on slow disks it is
 * unbounded.  Measured on two hosts with non-NCQ SATA SSDs: with each host
 * writing 4 x QD16 x 1 MiB, one 512-byte replicated write took up to 21-34 s;
 * MXFS's heartbeat is four of them, its authority lease 30 s, and both hosts
 * self-fenced under eight VM installs.  With each host's writes bounded to
 * 4 MiB in flight the same write took at most 1.3-1.8 s, at 35 MB/s against
 * 48 unbounded (scripts/drbd_write_latency_probe.sh).
 *
 * WHAT IT BOUNDS.  Data writes (direct and buffered) and metadata buffer
 * writes, which feed both disks through replication.  Metadata writes are
 * admitted ahead of waiting data writes, so log space keeps draining under a
 * data flood.  Reads are not bounded: DRBD serves them from the local disk,
 * never replicates them, and the disk scheduler already lets them past queued
 * writes, which a first-come gate would undo.  The log, and every coordination
 * write (the mxfs_pal_bio_* and mxfs_pal_bdev_* paths), never pass through it.
 *
 * A write the gate held is re-asked the mount's authority question when it is
 * released, so time spent waiting here can never carry a write past this
 * node's authority lease.
 */
#ifndef MXFS_IOQ_H
#define MXFS_IOQ_H

#include <linux/types.h>

struct bio;
struct block_device;
struct mxfs_ioq;

enum mxfs_ioq_class {
	MXFS_IOQ_META = 0,	/* metadata buffer writes: admitted before data */
	MXFS_IOQ_DATA = 1,	/* direct and buffered data writes */
	MXFS_IOQ_NCLASS
};

/*
 * The bound for the mount on `bdev`, or NULL when the device has no DRBD
 * attachment on this node (nothing is bounded then).  `admitted(ctx)` is the
 * mount's authority question, asked again for each write the gate held.
 */
struct mxfs_ioq *mxfs_pal_ioq_create(struct block_device *bdev,
				     bool (*admitted)(void *ctx), void *ctx);
/* The mount is gone; the gate is freed once its last write completes. */
void mxfs_pal_ioq_destroy(struct mxfs_ioq *q);

/*
 * Admit `bio` before its submitter submits it.  A bio larger than one piece
 * (a quarter of the byte bound, at most 1 MiB) is split from the front first,
 * each piece chained to what is left and submitted here as soon as it is
 * admitted; what is left is admitted last and handed back for the caller to
 * submit.  Each admission waits (uninterruptibly, in class order, first come
 * first served) until its bytes fit under the bound, then hooks the piece's
 * completion so finishing it frees that share.  `ahead` is 0, except for the
 * last bio of a span whose earlier bios were already submitted chained to it
 * (a writeback ioend on a kernel whose iomap still chains them): their bytes,
 * charged to the first piece admitted and held until it ends.
 *
 * The hook keeps the bio's completion and calls it, so admission comes last,
 * once that completion is final, and the caller submits next: a bio admitted
 * and not yet submitted holds a share nothing else can free.  Returns 0 when
 * the caller should submit it; -EAGAIN for a REQ_NOWAIT bio that does not fit
 * now (nothing taken, nothing hooked, never split); -EIO when the mount's
 * authority closed while a piece waited — the caller must complete the bio
 * with an error, never submit it.  A read, a bio of a mount with no bound or
 * for another device, or any operation other than a plain write is admitted
 * at once, unhooked.
 */
int mxfs_pal_ioq_admit(struct mxfs_ioq *q, struct bio *bio,
		       enum mxfs_ioq_class cls, unsigned int ahead);
/* Admit the bio's own size, then submit_bio — or end the bio with the
 * refusal's status.  For every submission site that calls submit_bio itself. */
void mxfs_pal_ioq_submit(struct mxfs_ioq *q, struct bio *bio,
			 enum mxfs_ioq_class cls);

#endif /* MXFS_IOQ_H */
